"""Unit tests for the git source providers (CodeCommit, GitHub, local directory)."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import boto3
import pytest
import requests
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber
from requests.structures import CaseInsensitiveDict

from app.services.git_sources import providers
from app.services.git_sources.providers import (
    Change,
    CodeCommitProvider,
    CommitInfo,
    FileTooLargeError,
    GitHubProvider,
    GitSourceError,
    LocalDirectoryProvider,
    NotFoundError,
    RateLimitError,
    TreeEntry,
    build_provider,
)

REPO = "governance"


# --- CodeCommit -------------------------------------------------------------------


@pytest.fixture
def codecommit():
    client = boto3.client("codecommit", region_name="us-east-1", aws_access_key_id="testing",
                          aws_secret_access_key="testing")
    with Stubber(client) as stubber:
        yield CodeCommitProvider(REPO, "main", client), stubber
        stubber.assert_no_pending_responses()


def _differences(stubber, items, *, after, before=None, token=None, next_token=None):
    params = {"repositoryName": REPO, "afterCommitSpecifier": after}
    if before:
        params["beforeCommitSpecifier"] = before
    if token:
        params["NextToken"] = token
    response = {"differences": items}
    if next_token:
        response["NextToken"] = next_token
    stubber.add_response("get_differences", response, params)


def _blob(path, blob_id, mode="100644"):
    return {"path": path, "blobId": blob_id, "mode": mode}


def _commit(stubber, commit_id, parents, timestamp):
    person = {"name": "Ada", "email": "ada@example.com", "date": f"{timestamp} -0500"}
    stubber.add_response("get_commit", {"commit": {
        "commitId": commit_id, "treeId": "tree-" + commit_id, "parents": parents,
        "message": f"message {commit_id}", "author": person, "committer": person,
    }}, {"repositoryName": REPO, "commitId": commit_id})


def test_codecommit_resolve_head(codecommit):
    provider, stubber = codecommit
    stubber.add_response("get_branch", {"branch": {"branchName": "main", "commitId": "abc123"}},
                         {"repositoryName": REPO, "branchName": "main"})
    assert provider.resolve_head() == "abc123"
    assert provider.name == "codecommit"
    assert provider.max_file_bytes == 6 * 1024 * 1024
    assert provider.supports_history is True


def test_codecommit_resolve_head_without_commit(codecommit):
    provider, stubber = codecommit
    stubber.add_response("get_branch", {"branch": {"branchName": "main"}},
                         {"repositoryName": REPO, "branchName": "main"})
    with pytest.raises(GitSourceError, match="has no commit"):
        provider.resolve_head()


@pytest.mark.parametrize("code", [
    "RepositoryDoesNotExistException", "BranchDoesNotExistException",
])
def test_codecommit_resolve_head_not_found(codecommit, code):
    provider, stubber = codecommit
    stubber.add_client_error("get_branch", service_error_code=code, service_message="missing",
                             http_status_code=400)
    with pytest.raises(NotFoundError, match=code):
        provider.resolve_head()


def test_codecommit_list_tree_paginates_and_skips_submodules(codecommit):
    provider, stubber = codecommit
    _differences(stubber, [
        {"afterBlob": _blob("policies/b.md", "b1"), "changeType": "A"},
        {"afterBlob": _blob("vendor/lib", "c0ffee", mode="160000"), "changeType": "A"},
    ], after="head", next_token="page-2")
    _differences(stubber, [
        {"afterBlob": _blob("/a.md", "a1"), "changeType": "A"},
        {"afterBlob": {"path": "no-blob-id"}, "changeType": "A"},
    ], after="head", token="page-2")
    assert provider.list_tree("head") == [
        TreeEntry("a.md", "a1", None),
        TreeEntry("policies/b.md", "b1", None),
    ]


def test_codecommit_diff_add_modify_delete_paginated(codecommit):
    provider, stubber = codecommit
    _differences(stubber, [
        {"afterBlob": _blob("new.md", "n1"), "changeType": "A"},
        {"beforeBlob": _blob("changed.md", "c1"), "afterBlob": _blob("changed.md", "c2"),
         "changeType": "M"},
    ], before="old", after="new", next_token="t2")
    _differences(stubber, [
        {"beforeBlob": _blob("gone.md", "g1"), "changeType": "D"},
        {"beforeBlob": _blob("from.md", "f1"), "afterBlob": _blob("to.md", "f1"), "changeType": "M"},
        {"beforeBlob": _blob("sub", "s1", mode="160000"), "afterBlob": _blob("sub", "s2", mode="160000"),
         "changeType": "M"},
        {"beforeBlob": _blob("was-sub", "s1", mode="160000"), "afterBlob": _blob("was-sub", "w1"),
         "changeType": "M"},
    ], before="old", after="new", token="t2")
    assert provider.diff("old", "new") == [
        Change("changed.md", "M", "c2"),
        Change("from.md", "D", None),
        Change("gone.md", "D", None),
        Change("new.md", "A", "n1"),
        Change("to.md", "A", "f1"),
        Change("was-sub", "A", "w1"),
    ]


def test_codecommit_diff_same_commit_makes_no_call(codecommit):
    provider, _ = codecommit
    assert provider.diff("same", "same") == []


def test_codecommit_read_blob_by_id_and_entry(codecommit):
    provider, stubber = codecommit
    for _ in range(2):
        stubber.add_response("get_blob", {"content": b"hello"}, {"repositoryName": REPO, "blobId": "b1"})
    assert provider.read_blob("b1") == b"hello"
    assert provider.read_blob(TreeEntry("a.md", "b1", 5)) == b"hello"


def test_codecommit_read_blob_too_large(codecommit):
    provider, stubber = codecommit
    stubber.add_client_error("get_blob", service_error_code="FileTooLargeException",
                             service_message="The file is too large", http_status_code=400)
    with pytest.raises(FileTooLargeError) as caught:
        provider.read_blob("b1", path="big.bin")
    assert caught.value.path == "big.bin"
    assert caught.value.size is None
    assert caught.value.limit == 6 * 1024 * 1024
    assert "6 MB" in str(caught.value)


def test_codecommit_read_blob_known_size_over_limit_makes_no_call(codecommit):
    provider, _ = codecommit
    with pytest.raises(FileTooLargeError) as caught:
        provider.read_blob(TreeEntry("big.bin", "b1", 7 * 1024 * 1024))
    assert caught.value.size == 7 * 1024 * 1024
    assert "big.bin" in str(caught.value)


def test_codecommit_read_blob_of_deletion_is_rejected(codecommit):
    provider, _ = codecommit
    with pytest.raises(GitSourceError, match="was deleted"):
        provider.read_blob(Change("gone.md", "D", None))
    with pytest.raises(GitSourceError, match="blob id is required"):
        provider.read_blob("")


def test_codecommit_read_blob_from_change(codecommit):
    provider, stubber = codecommit
    stubber.add_response("get_blob", {"content": b"x"}, {"repositoryName": REPO, "blobId": "n1"})
    assert provider.read_blob(Change("new.md", "A", "n1")) == b"x"


def test_codecommit_read_file(codecommit):
    provider, stubber = codecommit
    stubber.add_response("get_file", {
        "commitId": "head", "blobId": "b1", "filePath": "policies/a.md", "fileMode": "NORMAL",
        "fileSize": 5, "fileContent": b"hello",
    }, {"repositoryName": REPO, "commitSpecifier": "head", "filePath": "policies/a.md"})
    assert provider.read_file("policies/a.md", "head") == b"hello"


def test_codecommit_read_file_errors(codecommit):
    provider, stubber = codecommit
    stubber.add_client_error("get_file", service_error_code="FileTooLargeException",
                             service_message="too large", http_status_code=400)
    stubber.add_client_error("get_file", service_error_code="FileDoesNotExistException",
                             service_message="no such file", http_status_code=400)
    stubber.add_client_error("get_file", service_error_code="EncryptionKeyAccessDeniedException",
                             service_message="denied", http_status_code=400)
    with pytest.raises(FileTooLargeError) as caught:
        provider.read_file("big.bin", "head")
    assert caught.value.path == "big.bin"
    with pytest.raises(NotFoundError, match="FileDoesNotExistException: no such file"):
        provider.read_file("missing.md", "head")
    with pytest.raises(GitSourceError, match="EncryptionKeyAccessDeniedException: denied") as other:
        provider.read_file("a.md", "head")
    assert not isinstance(other.value, NotFoundError)


def test_codecommit_error_without_message():
    client = mock.Mock()
    client.get_branch.side_effect = providers.ClientError({"Error": {"Code": "Throttling"}}, "GetBranch")
    with pytest.raises(GitSourceError, match="^CodeCommit Throttling$"):
        CodeCommitProvider(REPO, "main", client).resolve_head()


def test_codecommit_read_file_rejects_unsafe_path(codecommit):
    provider, _ = codecommit
    for path in ("../x", "/abs.md", "a//b", ""):
        with pytest.raises(GitSourceError, match="invalid repository path"):
            provider.read_file(path, "head")


def test_codecommit_botocore_error_is_wrapped():
    client = mock.Mock()
    client.get_branch.side_effect = EndpointConnectionError(endpoint_url="https://codecommit.invalid")
    with pytest.raises(GitSourceError, match="CodeCommit request failed"):
        CodeCommitProvider(REPO, "main", client).resolve_head()


def _merge_graph(stubber, order):
    """Queue GetCommit responses for the graph below in the order the walk requests them.

    R(100) <- A(200) <- B(300) <-------- M(400) <- C(500)
                   \\<- F1(250) <- F2(350) <-/
    """
    graph = {"R": ([], 100), "A": (["R"], 200), "B": (["A"], 300), "F1": (["A"], 250),
             "F2": (["F1"], 350), "M": (["B", "F2"], 400), "C": (["M"], 500)}
    for commit_id in order:
        parents, timestamp = graph[commit_id]
        _commit(stubber, commit_id, parents, timestamp)


def test_codecommit_commits_between_merge_stops_at_from(codecommit):
    provider, stubber = codecommit
    _merge_graph(stubber, ["C", "B", "M", "F2", "F1", "A"])
    commits = provider.commits_between("B", "C", 10)
    assert [commit.commit_id for commit in commits] == ["C", "M", "F2", "F1"]
    merge = commits[1]
    assert merge.parent_ids == ("B", "F2")
    assert merge.author_name == "Ada"
    assert merge.author_email == "ada@example.com"
    assert merge.committed_at == datetime.fromtimestamp(400, tz=timezone.utc)
    assert merge.authored_at.tzinfo is not None
    assert merge.message == "message M"


def test_codecommit_commits_between_respects_limit(codecommit):
    provider, stubber = codecommit
    _merge_graph(stubber, ["C", "B", "M"])
    assert [c.commit_id for c in provider.commits_between("B", "C", 2)] == ["C", "M"]


def test_codecommit_commits_between_from_root_visits_each_commit_once(codecommit):
    provider, stubber = codecommit
    _merge_graph(stubber, ["C", "M", "B", "F2", "F1", "A", "R"])
    commits = provider.commits_between(None, "C", 100)
    assert [c.commit_id for c in commits] == ["C", "M", "F2", "B", "F1", "A", "R"]


def test_codecommit_commits_between_trivial_ranges(codecommit):
    provider, _ = codecommit
    assert provider.commits_between("C", "C", 10) == []
    assert provider.commits_between(None, "C", 0) == []


def test_codecommit_commits_between_corrects_clock_skew(codecommit):
    """P is an ancestor of the excluded commit U but is dated after it."""
    provider, stubber = codecommit
    _commit(stubber, "T", ["S"], 500)
    _commit(stubber, "U", ["P"], 400)
    _commit(stubber, "S", ["P"], 470)
    _commit(stubber, "P", ["Q"], 450)
    _commit(stubber, "Q", [], 10)
    assert [c.commit_id for c in provider.commits_between("U", "T", 10)] == ["T", "S"]


def test_codecommit_commits_between_walks_shared_uninteresting_ancestors_once(codecommit):
    """U's parents W1 and W2 are both excluded; W2 is reached twice but fetched once."""
    provider, stubber = codecommit
    _commit(stubber, "T", ["X"], 500)
    _commit(stubber, "U", ["W1", "W2"], 400)
    _commit(stubber, "X", [], 100)
    _commit(stubber, "W1", ["W2"], 390)
    _commit(stubber, "W2", [], 380)
    assert [c.commit_id for c in provider.commits_between("U", "T", 10)] == ["T", "X"]


def test_codecommit_commit_dates_accept_iso_and_missing():
    client = mock.Mock()
    client.get_commit.side_effect = [
        {"commit": {
            "parents": [], "message": None,
            "author": {"name": "Ada", "date": "2026-01-02T03:04:05"},
            "committer": {"date": "not a date"},
        }},
        {"commit": {"parents": ["p1"], "message": "no dates"}},
    ]
    provider = CodeCommitProvider(REPO, "main", client)
    commit = provider._get_commit("x1")
    assert commit.commit_id == "x1"
    assert commit.authored_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert commit.committed_at is None
    assert commit.message == ""
    undated = provider._get_commit("x2")
    assert undated.authored_at is None and undated.committed_at is None
    assert undated.author_name is None


def test_codecommit_commit_changed_paths_first_parent(codecommit):
    provider, stubber = codecommit
    _differences(stubber, [
        {"afterBlob": _blob("new.md", "n1"), "changeType": "A"},
        {"beforeBlob": _blob("old.md", "o1"), "afterBlob": _blob("renamed.md", "o1"), "changeType": "M"},
    ], before="P1", after="M", next_token="t2")
    _differences(stubber, [{"beforeBlob": _blob("gone.md", "g1"), "changeType": "D"}],
                 before="P1", after="M", token="t2")
    merge = CommitInfo("M", ("P1", "P2"), None, None, None, None, None, None, "merge")
    assert provider.commit_changed_paths(merge) == ["gone.md", "new.md", "old.md", "renamed.md"]


def test_codecommit_commit_changed_paths_root_commit(codecommit):
    provider, stubber = codecommit
    _differences(stubber, [{"afterBlob": _blob("a.md", "a1"), "changeType": "A"}], after="R")
    root = CommitInfo("R", (), None, None, None, None, None, None, "initial")
    assert provider.commit_changed_paths(root) == ["a.md"]


@pytest.mark.parametrize("repository", ["", "has space", "x" * 101, None])
def test_codecommit_rejects_invalid_repository(repository):
    with pytest.raises(GitSourceError, match="invalid CodeCommit repository"):
        CodeCommitProvider(repository, "main", mock.Mock())


# --- GitHub -------------------------------------------------------------------------

API = "https://api.github.com"
PREFIX = API + "/repos/acme/policies"
TOKEN = "ghp_exampletokenvalue0123456789"
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
PUBLIC_ADDRESS = "140.82.121.6"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Every host name resolves to a public address; no test makes a DNS lookup."""
    import socket

    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def _response(status=200, body=None, content=None, headers=None):
    response = requests.Response()
    response.status_code = status
    if content is None:
        content = json.dumps(body).encode() if body is not None else b""
    response._content = content
    response.headers = CaseInsensitiveDict(headers or {})
    return response


def _params_key(params):
    return tuple(sorted((key, str(value)) for key, value in (params or {}).items()))


class FakeGitHub:
    """A ``requests.Session`` mock that answers from a route table."""

    def __init__(self):
        self.routes = {}
        self.calls = []
        self.session = mock.Mock(spec=requests.Session)
        self.session.get.side_effect = self._get

    def add(self, path, response, params=None):
        self.routes[(path, _params_key(params))] = response

    def _get(self, url, headers=None, params=None, timeout=None, allow_redirects=True):
        assert url.startswith(PREFIX)
        assert allow_redirects is False  # redirects are followed (and checked) by safe_get
        key = (url[len(PREFIX):], _params_key(params))
        self.calls.append({"path": key[0], "params": params, "headers": headers, "timeout": timeout})
        if key not in self.routes:
            raise AssertionError(f"unexpected GitHub call {key}")
        return self.routes[key]


@pytest.fixture
def github():
    fake = FakeGitHub()
    provider = GitHubProvider("acme/policies", "main", token=TOKEN, session=fake.session,
                              request_timeout=12.5)
    return provider, fake


def test_github_resolve_head_sends_headers(github):
    provider, fake = github
    fake.add("/branches/main", _response(body={"name": "main", "commit": {"sha": SHA_A}}))
    assert provider.resolve_head() == SHA_A
    headers = fake.calls[0]["headers"]
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert fake.calls[0]["timeout"] == 12.5
    assert provider.max_file_bytes == 100 * 1024 * 1024


def test_github_without_token_sends_no_authorization():
    fake = FakeGitHub()
    provider = GitHubProvider("acme/policies", "release/v1", session=fake.session)
    fake.add("/branches/release/v1", _response(body={"commit": {"sha": SHA_B}}))
    assert provider.resolve_head() == SHA_B
    assert "Authorization" not in fake.calls[0]["headers"]


def test_github_resolve_head_invalid_responses(github):
    provider, fake = github
    fake.add("/branches/main", _response(body={"commit": {}}))
    with pytest.raises(GitSourceError, match="has no commit"):
        provider.resolve_head()
    fake.add("/branches/main", _response(content=b"<html>"))
    with pytest.raises(GitSourceError, match="invalid response for the branch"):
        provider.resolve_head()


def test_github_list_tree(github):
    provider, fake = github
    fake.add(f"/git/trees/{SHA_A}", _response(body={"sha": "t", "truncated": False, "tree": [
        {"path": "policies", "type": "tree", "sha": "d" * 40},
        {"path": "policies/b.md", "type": "blob", "sha": SHA_B, "size": 12, "mode": "100644"},
        {"path": "a.md", "type": "blob", "sha": SHA_C, "size": 3, "mode": "100644"},
        {"path": "vendor/lib", "type": "commit", "sha": "e" * 40},
    ]}), params={"recursive": "1"})
    assert provider.list_tree(SHA_A) == [TreeEntry("a.md", SHA_C, 3), TreeEntry("policies/b.md", SHA_B, 12)]


def test_github_list_tree_truncated(github):
    provider, fake = github
    fake.add(f"/git/trees/{SHA_A}", _response(body={"truncated": True, "tree": []}),
             params={"recursive": "1"})
    with pytest.raises(GitSourceError, match="100,000 entries or 7 MB"):
        provider.list_tree(SHA_A)


def test_github_rejects_invalid_object_ids(github):
    provider, _ = github
    with pytest.raises(GitSourceError, match="invalid git object id"):
        provider.list_tree("../../user")
    with pytest.raises(GitSourceError, match="invalid git object id"):
        provider.commits_between(None, "main", 5)


def test_github_diff_uses_compare(github):
    provider, fake = github
    fake.add(f"/compare/{SHA_A}...{SHA_B}", _response(body={"status": "ahead", "files": [
        {"filename": "added.md", "status": "added", "sha": "1" * 40},
        {"filename": "changed.md", "status": "modified", "sha": "2" * 40},
        {"filename": "removed.md", "status": "removed", "sha": "3" * 40},
        {"filename": "new-name.md", "previous_filename": "old-name.md", "status": "renamed", "sha": "4" * 40},
        {"filename": "copy.md", "status": "copied", "sha": "5" * 40},
        {"filename": "mode.sh", "status": "changed", "sha": "6" * 40},
        {"filename": "same.md", "status": "unchanged", "sha": "7" * 40},
    ]}))
    assert provider.diff(SHA_A, SHA_B) == [
        Change("added.md", "A", "1" * 40),
        Change("changed.md", "M", "2" * 40),
        Change("copy.md", "A", "5" * 40),
        Change("mode.sh", "M", "6" * 40),
        Change("new-name.md", "A", "4" * 40),
        Change("old-name.md", "D", None),
        Change("removed.md", "D", None),
    ]
    assert len(fake.calls) == 1


def test_github_diff_rename_onto_readded_path_is_modification(github):
    provider, fake = github
    fake.add(f"/compare/{SHA_A}...{SHA_B}", _response(body={"status": "ahead", "files": [
        {"filename": "b.md", "previous_filename": "a.md", "status": "renamed", "sha": "1" * 40},
        {"filename": "a.md", "status": "added", "sha": "2" * 40},
    ]}))
    assert provider.diff(SHA_A, SHA_B) == [Change("a.md", "M", "2" * 40), Change("b.md", "A", "1" * 40)]


def test_github_diff_same_commit(github):
    provider, fake = github
    assert provider.diff(SHA_A, SHA_A) == []
    assert fake.calls == []


def _trees(fake):
    fake.add(f"/git/trees/{SHA_A}", _response(body={"tree": [
        {"path": "keep.md", "type": "blob", "sha": "1" * 40, "size": 1},
        {"path": "edit.md", "type": "blob", "sha": "2" * 40, "size": 1},
        {"path": "drop.md", "type": "blob", "sha": "3" * 40, "size": 1},
    ]}), params={"recursive": "1"})
    fake.add(f"/git/trees/{SHA_B}", _response(body={"tree": [
        {"path": "keep.md", "type": "blob", "sha": "1" * 40, "size": 1},
        {"path": "edit.md", "type": "blob", "sha": "9" * 40, "size": 1},
        {"path": "add.md", "type": "blob", "sha": "4" * 40, "size": 1},
    ]}), params={"recursive": "1"})


TREE_DIFF = [
    Change("add.md", "A", "4" * 40),
    Change("drop.md", "D", None),
    Change("edit.md", "M", "9" * 40),
]


def test_github_diff_falls_back_to_trees_at_300_files(github):
    provider, fake = github
    files = [{"filename": f"f{i}.md", "status": "added", "sha": "1" * 40} for i in range(300)]
    fake.add(f"/compare/{SHA_A}...{SHA_B}", _response(body={"status": "ahead", "files": files}))
    _trees(fake)
    assert provider.diff(SHA_A, SHA_B) == TREE_DIFF
    assert [call["path"] for call in fake.calls][1:] == [f"/git/trees/{SHA_A}", f"/git/trees/{SHA_B}"]


@pytest.mark.parametrize("compare", [
    _response(body={"status": "diverged", "files": []}),
    _response(body={"status": "ahead"}),
    _response(body={"status": "ahead", "files": [{"filename": "x.md", "status": "added"}]}),
    _response(body={"status": "ahead", "files": [{"status": "added", "sha": "1" * 40}]}),
    _response(body={"status": "ahead",
                    "files": [{"filename": "x.md", "status": "renamed", "sha": "1" * 40}]}),
    _response(body={"status": "ahead", "files": [{"filename": "x.md", "status": "odd", "sha": "1" * 40}]}),
    _response(status=500, body={"message": "Server Error"}),
])
def test_github_diff_falls_back_to_trees_when_compare_is_incomplete(github, compare):
    provider, fake = github
    fake.add(f"/compare/{SHA_A}...{SHA_B}", compare)
    _trees(fake)
    assert provider.diff(SHA_A, SHA_B) == TREE_DIFF


def test_github_diff_compare_not_found_is_raised(github):
    provider, fake = github
    fake.add(f"/compare/{SHA_A}...{SHA_B}", _response(status=404, body={"message": "Not Found"}))
    with pytest.raises(NotFoundError):
        provider.diff(SHA_A, SHA_B)


def test_github_read_blob_raw(github):
    provider, fake = github
    fake.add(f"/git/blobs/{SHA_B}", _response(content=b"\x00binary\xff"))
    assert provider.read_blob(TreeEntry("img.png", SHA_B, 9)) == b"\x00binary\xff"
    assert fake.calls[0]["headers"]["Accept"] == "application/vnd.github.raw+json"


def test_github_read_blob_known_size_over_limit_makes_no_call(github):
    provider, fake = github
    with pytest.raises(FileTooLargeError) as caught:
        provider.read_blob(TreeEntry("huge.bin", SHA_B, 101 * 1024 * 1024))
    assert caught.value.limit == 100 * 1024 * 1024
    assert fake.calls == []


def test_github_read_file_raw_with_ref(github):
    provider, fake = github
    fake.add("/contents/policies/access%20control.md", _response(content=b"# Access"),
             params={"ref": SHA_A})
    assert provider.read_file("policies/access control.md", SHA_A) == b"# Access"
    assert fake.calls[0]["headers"]["Accept"] == "application/vnd.github.raw+json"
    with pytest.raises(GitSourceError, match="invalid repository path"):
        provider.read_file("../../../user", SHA_A)


def test_github_not_found(github):
    provider, fake = github
    fake.add(f"/git/blobs/{SHA_C}", _response(status=404, body={"message": "Not Found"}))
    with pytest.raises(NotFoundError, match="not found"):
        provider.read_blob(SHA_C)


def test_github_too_large(github):
    provider, fake = github
    fake.add(f"/git/blobs/{SHA_C}", _response(status=403, body={
        "message": "This API returns blobs up to 100 MB in size.",
        "errors": [{"resource": "Blob", "field": "data", "code": "too_large"}],
    }))
    fake.add("/contents/big.bin", _response(status=403, body={"message": "File is too large"}),
             params={"ref": SHA_A})
    with pytest.raises(FileTooLargeError) as blob_error:
        provider.read_blob(SHA_C, path="big.bin")
    assert blob_error.value.path == "big.bin"
    assert blob_error.value.limit == 100 * 1024 * 1024
    with pytest.raises(FileTooLargeError):
        provider.read_file("big.bin", SHA_A)


def test_github_rate_limit_with_reset(github):
    provider, fake = github
    fake.add("/branches/main", _response(status=403, body={"message": "API rate limit exceeded"},
                                         headers={"X-RateLimit-Remaining": "0",
                                                  "X-RateLimit-Reset": "1120"}))
    with mock.patch.object(providers, "time") as fake_time:
        fake_time.time.return_value = 1000.0
        with pytest.raises(RateLimitError, match="retry after 120 seconds") as caught:
            provider.resolve_head()
    assert caught.value.retry_after == 120


def test_github_rate_limit_retry_after(github):
    provider, fake = github
    fake.add("/branches/main", _response(status=429, body={"message": "slow down"},
                                         headers={"Retry-After": "30"}))
    with pytest.raises(RateLimitError) as caught:
        provider.resolve_head()
    assert caught.value.retry_after == 30


def test_github_secondary_rate_limit_without_wait(github):
    provider, fake = github
    fake.add("/branches/main", _response(status=429, content=b"too many requests"))
    with pytest.raises(RateLimitError) as caught:
        provider.resolve_head()
    assert caught.value.retry_after is None


@pytest.mark.parametrize("status,body,pattern", [
    (401, {"message": "Bad credentials"}, "rejected the credentials"),
    (403, {"message": "Resource not accessible by integration"}, "error 403.*not accessible"),
    (500, None, "error 500"),
    (502, ["unexpected"], "error 502"),
])
def test_github_other_errors(github, status, body, pattern):
    provider, fake = github
    fake.add("/branches/main", _response(status=status, body=body))
    with pytest.raises(GitSourceError, match=pattern) as caught:
        provider.resolve_head()
    assert not isinstance(caught.value, (NotFoundError, RateLimitError, FileTooLargeError))


def test_github_token_never_appears_in_errors(github):
    provider, fake = github
    fake.add("/branches/main", _response(status=500, body={"message": f"echo {TOKEN}"}))
    with pytest.raises(GitSourceError) as server_error:
        provider.resolve_head()
    assert TOKEN not in str(server_error.value)
    assert "***" in str(server_error.value)
    fake.session.get.side_effect = requests.ConnectionError(f"connection reset (token {TOKEN})")
    with pytest.raises(GitSourceError, match="ConnectionError") as network_error:
        provider.resolve_head()
    assert TOKEN not in str(network_error.value)
    assert network_error.value.__cause__ is None


def _gh_commit(sha, parents, date="2026-05-01T10:00:00Z"):
    person = {"name": "Grace", "email": "grace@example.com", "date": date}
    return {"sha": sha, "parents": [{"sha": parent} for parent in parents],
            "commit": {"author": person, "committer": person, "message": f"message {sha[:4]}"}}


def test_github_commits_between_uses_compare(github):
    provider, fake = github
    shas = [f"{i:040x}" for i in range(1, 4)]
    fake.add(f"/compare/{SHA_A}...{SHA_B}", _response(body={
        "total_commits": 3,
        "commits": [_gh_commit(shas[0], [SHA_A]), _gh_commit(shas[1], [shas[0]]),
                    _gh_commit(shas[2], [shas[1]], date="2026-05-01T12:00:00+02:00")],
    }))
    commits = provider.commits_between(SHA_A, SHA_B, 2)
    assert [c.commit_id for c in commits] == [shas[2], shas[1]]
    assert commits[0].parent_ids == (shas[1],)
    assert commits[0].committed_at == datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    assert commits[0].author_email == "grace@example.com"
    assert commits[0].message == "message 0000"


def _list_page(fake, page, items):
    fake.add("/commits", _response(body=items), params={"sha": SHA_B, "per_page": 100, "page": page})


def test_github_commits_between_large_range_walks_list_until_from(github):
    provider, fake = github
    fake.add(f"/compare/{SHA_A}...{SHA_B}", _response(body={
        "total_commits": 400, "commits": [_gh_commit(SHA_C, [SHA_A])]}))
    page_one = [_gh_commit(f"{i:040x}", [f"{i + 1:040x}"]) for i in range(1, 101)]
    page_one[50] = page_one[49]
    page_two = [_gh_commit(f"{i:040x}", []) for i in range(101, 104)] + [_gh_commit(SHA_A, [])]
    page_two += [_gh_commit(f"{i:040x}", []) for i in range(200, 296)]
    _list_page(fake, 1, page_one)
    _list_page(fake, 2, page_two)
    commits = provider.commits_between(SHA_A, SHA_B, 1000)
    assert len(commits) == 99 + 3
    assert commits[-1].commit_id == f"{103:040x}"
    assert len({c.commit_id for c in commits}) == len(commits)


def test_github_commits_between_from_root_respects_limit(github):
    provider, fake = github
    _list_page(fake, 1, [_gh_commit(f"{i:040x}", []) for i in range(1, 101)])
    _list_page(fake, 2, [_gh_commit(f"{i:040x}", []) for i in range(101, 201)])
    commits = provider.commits_between(None, SHA_B, 150)
    assert len(commits) == 150
    assert commits[-1].commit_id == f"{150:040x}"


def test_github_commits_between_short_history(github):
    provider, fake = github
    _list_page(fake, 1, [_gh_commit(SHA_C, []), {"parents": []}])
    assert [c.commit_id for c in provider.commits_between(None, SHA_B, 10)] == [SHA_C]
    assert provider.commits_between(SHA_B, SHA_B, 10) == []
    assert provider.commits_between(None, SHA_B, 0) == []


def test_github_commit_changed_paths_paginates(github):
    provider, fake = github
    first = [{"filename": f"f{i:03}.md"} for i in range(99)]
    first.append({"filename": "new.md", "previous_filename": "old.md"})
    fake.add(f"/commits/{SHA_C}", _response(body={"files": first}), params={"per_page": 100, "page": 1})
    fake.add(f"/commits/{SHA_C}", _response(body={"files": [{"filename": "last.md"}]}),
             params={"per_page": 100, "page": 2})
    commit = CommitInfo(SHA_C, (SHA_A, SHA_B), None, None, None, None, None, None, "merge")
    paths = provider.commit_changed_paths(commit)
    assert len(paths) == 102
    assert {"new.md", "old.md", "last.md"} <= set(paths)
    assert paths == sorted(paths)


@pytest.mark.parametrize("repository", ["acme", "acme/policies/extra", "acme/..", "ac me/x", None])
def test_github_rejects_invalid_repository(repository):
    with pytest.raises(GitSourceError, match="owner/name"):
        GitHubProvider(repository, "main", session=mock.Mock())


@pytest.mark.parametrize("api_url", ["http://api.github.com", "ftp://x", "https://", "https://u:p@host",
                                     "https://host/api?x=1"])
def test_github_rejects_invalid_api_url(api_url):
    with pytest.raises(GitSourceError, match="https://"):
        GitHubProvider("acme/policies", "main", api_url=api_url, session=mock.Mock())


def test_github_enterprise_api_url():
    fake = mock.Mock(spec=requests.Session)
    fake.get.return_value = _response(body={"commit": {"sha": SHA_A}})
    provider = GitHubProvider("acme/policies", "main", api_url="https://git.example.com/api/v3/",
                              session=fake)
    assert provider.resolve_head() == SHA_A
    assert fake.get.call_args.args[0] == "https://git.example.com/api/v3/repos/acme/policies/branches/main"


@pytest.mark.parametrize("branch", ["", "  ", "a..b", "-x", "feature/", "has space", "x.lock", "a//b",
                                    "a@{1}", None])
def test_invalid_branch_names_are_rejected(branch):
    with pytest.raises(GitSourceError, match="branch"):
        GitHubProvider("acme/policies", branch, session=mock.Mock())


# --- local directory ------------------------------------------------------------------


def _write(root, rel, content):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _sha(content):
    return hashlib.sha256(content).hexdigest()


@pytest.fixture
def local_root(tmp_path):
    root = tmp_path / "repo"
    _write(root, "README.md", b"readme")
    _write(root, "policies/access.md", b"access policy")
    _write(root, "evidence/2026/q1.json", b"{}")
    _write(root, ".git/config", b"[core]")
    _write(root, ".github/workflows/ci.yml", b"on: push")
    _write(root, ".gitignore", b"*.tmp")
    _write(root, "docs/.gitkeep", b"")
    return root


def test_local_lists_tree_and_skips_git_paths(local_root):
    provider = LocalDirectoryProvider(local_root)
    head = provider.resolve_head()
    assert head.startswith("local-") and len(head) == len("local-") + 40
    assert provider.list_tree(head) == [
        TreeEntry("README.md", _sha(b"readme"), 6),
        TreeEntry("evidence/2026/q1.json", _sha(b"{}"), 2),
        TreeEntry("policies/access.md", _sha(b"access policy"), 13),
    ]
    assert provider.name == "local"
    assert provider.max_file_bytes is None
    assert provider.supports_history is False


def test_local_head_is_stable_across_instances(local_root):
    head = LocalDirectoryProvider(local_root).resolve_head()
    other = LocalDirectoryProvider(str(local_root))
    assert other.resolve_head() == head
    assert other.resolve_head() == head
    assert other.list_tree(head)


def test_local_head_matches_documented_manifest(local_root):
    manifest = "".join(f"{path}\0{_sha(content)}\n" for path, content in sorted({
        "README.md": b"readme", "evidence/2026/q1.json": b"{}", "policies/access.md": b"access policy",
    }.items()))
    expected = "local-" + hashlib.sha256(manifest.encode()).hexdigest()[:40]
    assert LocalDirectoryProvider(local_root).resolve_head() == expected


def test_local_diff_after_add_modify_delete(local_root):
    provider = LocalDirectoryProvider(local_root)
    before = provider.resolve_head()
    _write(local_root, "policies/new.md", b"new")
    _write(local_root, "README.md", b"readme, revised")
    (local_root / "evidence/2026/q1.json").unlink()
    _write(local_root, ".git/HEAD", b"ref: refs/heads/main")
    after = provider.resolve_head()
    assert after != before
    assert provider.diff(before, after) == [
        Change("README.md", "M", _sha(b"readme, revised")),
        Change("evidence/2026/q1.json", "D", None),
        Change("policies/new.md", "A", _sha(b"new")),
    ]
    assert provider.diff(after, after) == []


def test_local_diff_unknown_from_snapshot(local_root):
    provider = LocalDirectoryProvider(local_root)
    head = provider.resolve_head()
    with pytest.raises(GitSourceError, match="unknown local snapshot"):
        provider.diff("local-" + "0" * 40, head)
    with pytest.raises(GitSourceError, match="unknown local snapshot"):
        provider.list_tree("local-" + "1" * 40)


def test_local_diff_from_head_of_unchanged_directory_after_restart(local_root):
    head = LocalDirectoryProvider(local_root).resolve_head()
    restarted = LocalDirectoryProvider(local_root)
    assert restarted.diff(head, head) == []
    assert restarted.list_tree(head)[0].path == "README.md"


def test_local_read_blob_and_file(local_root):
    provider = LocalDirectoryProvider(local_root)
    head = provider.resolve_head()
    entry = provider.list_tree(head)[2]
    assert provider.read_blob(entry) == b"access policy"
    assert provider.read_blob(entry.blob_id, commit_id=head) == b"access policy"
    assert provider.read_blob(entry.blob_id) == b"access policy"
    assert provider.read_file("policies/access.md", head) == b"access policy"
    with pytest.raises(NotFoundError):
        provider.read_file("policies/missing.md", head)
    with pytest.raises(NotFoundError, match="not in any listed local snapshot"):
        provider.read_blob("f" * 64)


def test_local_read_blob_detects_changed_file(local_root):
    provider = LocalDirectoryProvider(local_root)
    head = provider.resolve_head()
    entry = provider.list_tree(head)[0]
    _write(local_root, "README.md", b"tampered")
    with pytest.raises(GitSourceError, match="changed after the local tree was listed"):
        provider.read_blob(entry)
    with pytest.raises(GitSourceError, match="changed after"):
        provider.read_file("README.md", head)


def test_local_rejects_escaping_and_git_paths(local_root, tmp_path):
    outside = tmp_path / "outside"
    _write(outside, "secret.txt", b"secret")
    os.symlink(outside / "secret.txt", local_root / "leak.txt")
    os.symlink(outside, local_root / "leakdir")
    os.symlink(local_root / ".git" / "config", local_root / "gitconfig")
    os.symlink(local_root / "policies" / "access.md", local_root / "alias.md")
    os.symlink("loop", local_root / "loop")
    provider = LocalDirectoryProvider(local_root)
    head = provider.resolve_head()
    paths = [entry.path for entry in provider.list_tree(head)]
    assert paths == ["README.md", "alias.md", "evidence/2026/q1.json", "policies/access.md"]
    secret = _sha(b"secret")
    with pytest.raises(GitSourceError, match="outside the local source root"):
        provider.read_blob(secret, path="leak.txt")
    with pytest.raises(GitSourceError, match="outside the local source root"):
        provider.read_blob(secret, path="leakdir/secret.txt")
    with pytest.raises(GitSourceError, match="resolves into a .git path"):
        provider.read_blob(secret, path="gitconfig")
    with pytest.raises(GitSourceError, match="inside a .git path"):
        provider.read_blob(secret, path=".git/config")
    with pytest.raises(GitSourceError, match="cannot resolve"):
        provider.read_blob(secret, path="loop")
    with pytest.raises(NotFoundError, match="is not a file"):
        provider.read_blob(secret, path="policies")
    with pytest.raises(NotFoundError, match="does not exist"):
        provider.read_blob(secret, path="policies/missing.md")
    for unsafe in ("../outside/secret.txt", str(outside / "secret.txt"), "policies/../README.md"):
        with pytest.raises(GitSourceError, match="invalid repository path"):
            provider.read_blob(secret, path=unsafe)
    assert provider.read_blob(_sha(b"access policy"), path="alias.md") == b"access policy"


def test_local_reuses_hashes_of_unchanged_files(local_root):
    provider = LocalDirectoryProvider(local_root)
    with mock.patch.object(providers, "hashlib") as fake_hashlib:
        fake_hashlib.sha256.side_effect = hashlib.sha256
        provider.resolve_head()
        assert fake_hashlib.sha256.call_count == 3 + 1
        provider.resolve_head()
        assert fake_hashlib.sha256.call_count == 3 + 1 + 1
        _write(local_root, "README.md", b"readme v2")
        provider.resolve_head()
        assert fake_hashlib.sha256.call_count == 3 + 1 + 1 + 2


def test_local_forgets_old_snapshots(local_root):
    provider = LocalDirectoryProvider(local_root)
    provider.SNAPSHOT_LIMIT = 2
    first = provider.resolve_head()
    _write(local_root, "a.md", b"1")
    provider.resolve_head()
    _write(local_root, "b.md", b"2")
    latest = provider.resolve_head()
    with pytest.raises(GitSourceError, match="unknown local snapshot"):
        provider.diff(first, latest)


def test_local_unreadable_file(local_root):
    provider = LocalDirectoryProvider(local_root)
    with mock.patch.object(Path, "open", side_effect=PermissionError(13, "Permission denied")):
        with pytest.raises(GitSourceError, match="cannot read .*Permission denied"):
            provider.resolve_head()
    head = provider.resolve_head()
    with mock.patch.object(Path, "read_bytes", side_effect=PermissionError(13, "Permission denied")):
        with pytest.raises(GitSourceError, match="cannot read README.md"):
            provider.read_file("README.md", head)


def test_local_has_no_history(local_root):
    provider = LocalDirectoryProvider(local_root)
    head = provider.resolve_head()
    assert provider.commits_between(None, head, 10) == []
    commit = CommitInfo(head, (), None, None, None, None, None, None, "")
    assert provider.commit_changed_paths(commit) == []


def test_local_root_must_be_a_directory(tmp_path):
    with pytest.raises(GitSourceError, match="not a directory"):
        LocalDirectoryProvider(tmp_path / "missing")


# --- build_provider and errors ---------------------------------------------------------------


def test_build_codecommit_provider_uses_session():
    session = mock.Mock()
    provider = build_provider("CodeCommit", repository=REPO, branch="main", region="ca-central-1",
                              boto_session=session, request_timeout=7)
    assert isinstance(provider, CodeCommitProvider)
    args, kwargs = session.client.call_args
    assert args == ("codecommit",)
    assert kwargs["region_name"] == "ca-central-1"
    assert kwargs["config"].read_timeout == 7
    assert provider._client is session.client.return_value


def test_build_codecommit_provider_defaults_to_portal_session():
    with mock.patch("app.services.aws_session.get_session") as get_session:
        provider = build_provider("codecommit", repository=REPO, branch="main", region="us-west-2")
    get_session.assert_called_once_with("us-west-2")
    assert isinstance(provider, CodeCommitProvider)


def test_build_codecommit_provider_validates_before_building_a_client():
    session = mock.Mock()
    with pytest.raises(GitSourceError, match="invalid CodeCommit repository"):
        build_provider("codecommit", repository="bad name", branch="main", boto_session=session)
    with pytest.raises(GitSourceError, match="branch"):
        build_provider("codecommit", repository=REPO, branch="", boto_session=session)
    session.client.assert_not_called()


def test_build_github_provider():
    provider = build_provider("github", repository="acme/policies", branch="main", token=TOKEN,
                              request_timeout=5)
    assert isinstance(provider, GitHubProvider)
    assert provider.repository == "acme/policies"
    assert TOKEN not in repr(provider)
    enterprise = build_provider("github", repository="acme/policies", branch="main",
                                api_url="https://git.example.com/api/v3")
    assert enterprise._api_url == "https://git.example.com/api/v3"
    with pytest.raises(GitSourceError, match="owner/name"):
        build_provider("github", repository="policies", branch="main")


def test_build_local_provider(tmp_path):
    assert isinstance(build_provider("local", repository=str(tmp_path), branch="main"),
                      LocalDirectoryProvider)
    with pytest.raises(GitSourceError, match="not a directory"):
        build_provider("local", repository=str(tmp_path / "missing"), branch="main")
    with pytest.raises(GitSourceError, match="path of a directory"):
        build_provider("local", repository=" ", branch="main")


@pytest.mark.parametrize("name", ["gitlab", "", None])
def test_build_provider_rejects_unknown_provider(name):
    with pytest.raises(GitSourceError, match="unsupported git provider"):
        build_provider(name, repository="acme/policies", branch="main")


def test_build_provider_rejects_non_positive_timeout():
    with pytest.raises(GitSourceError, match="request_timeout"):
        build_provider("github", repository="acme/policies", branch="main", request_timeout=0)


# --- local-source policy (red-team finding 4) ------------------------------------------------


@pytest.fixture
def portal_env(monkeypatch):
    """Set PORTAL_ENV / LOCAL_SOURCE_ROOTS for one test."""
    def configure(environment, roots=None):
        monkeypatch.setenv("PORTAL_ENV", environment)
        if roots is None:
            monkeypatch.delenv("LOCAL_SOURCE_ROOTS", raising=False)
        else:
            monkeypatch.setenv("LOCAL_SOURCE_ROOTS", roots)
    return configure


def test_local_provider_is_disabled_in_production_without_roots(portal_env, tmp_path):
    portal_env("production")
    with pytest.raises(GitSourceError, match="disabled in production; set LOCAL_SOURCE_ROOTS"):
        build_provider("local", repository="/etc", branch="main")
    with pytest.raises(GitSourceError, match="disabled in production"):
        build_provider("local", repository=str(tmp_path), branch="main")


@pytest.mark.parametrize("environment", ["production", "development", "test"])
def test_local_provider_is_confined_to_local_source_roots(portal_env, tmp_path, environment):
    allowed = tmp_path / "srv"
    (allowed / "x").mkdir(parents=True)
    (allowed / "x" / "policy.md").write_text("# P\n")
    (tmp_path / "srv-other").mkdir()  # shares the root's name as a prefix, but is outside it
    portal_env(environment, f"{tmp_path / 'elsewhere'}:{allowed}")
    provider = build_provider("local", repository=str(allowed / "x"), branch="main")
    assert [e.path for e in provider.list_tree(provider.resolve_head())] == ["policy.md"]
    assert isinstance(build_provider("local", repository=str(allowed), branch="main"),
                      LocalDirectoryProvider)
    with pytest.raises(GitSourceError, match="outside LOCAL_SOURCE_ROOTS"):
        build_provider("local", repository="/etc", branch="main")
    with pytest.raises(GitSourceError, match="outside LOCAL_SOURCE_ROOTS"):
        build_provider("local", repository=str(tmp_path / "srv-other"), branch="main")


def test_local_provider_symlink_escape_is_rejected(portal_env, tmp_path):
    allowed = tmp_path / "srv"
    allowed.mkdir()
    (allowed / "etc-link").symlink_to("/etc")
    (allowed / "sub").mkdir()
    portal_env("production", str(allowed))
    with pytest.raises(GitSourceError, match="resolves to /etc, outside LOCAL_SOURCE_ROOTS"):
        build_provider("local", repository=str(allowed / "etc-link"), branch="main")
    with pytest.raises(GitSourceError, match="outside LOCAL_SOURCE_ROOTS"):
        build_provider("local", repository=str(allowed / "sub" / ".." / ".."), branch="main")
    assert build_provider("local", repository=str(allowed / "sub"), branch="main").root == \
        (allowed / "sub").resolve()


def test_local_provider_root_symlinked_into_a_root_is_allowed(portal_env, tmp_path):
    real = tmp_path / "data" / "evidence"
    real.mkdir(parents=True)
    (tmp_path / "alias").symlink_to(real)
    portal_env("production", str(tmp_path / "data"))
    assert build_provider("local", repository=str(tmp_path / "alias"), branch="main").root == real.resolve()


def test_local_directory_provider_allowed_roots_argument(tmp_path):
    with pytest.raises(GitSourceError, match="outside LOCAL_SOURCE_ROOTS \\(none\\)"):
        LocalDirectoryProvider(tmp_path, allowed_roots=[])
    assert LocalDirectoryProvider(tmp_path, allowed_roots=[str(tmp_path)]).root == tmp_path.resolve()
    assert LocalDirectoryProvider(tmp_path, allowed_roots=None).root == tmp_path.resolve()


def test_check_local_root_resolves_symlinks(tmp_path):
    (tmp_path / "link").symlink_to("/etc")
    assert providers.check_local_root(tmp_path / "link", None) == os.path.realpath("/etc")
    with pytest.raises(GitSourceError):
        providers.check_local_root(tmp_path / "link", [str(tmp_path)])


# --- GitHub api_url error bodies (red-team finding 8) ------------------------------------------


def test_github_errors_from_another_host_never_quote_the_response_body():
    session = mock.Mock(spec=requests.Session)
    provider = GitHubProvider("acme/policies", "main", api_url="https://ghe.example.com/api/v3",
                              session=session)
    for status, reason in ((500, "Internal Server Error"), (403, "Forbidden"), (422, "Unprocessable")):
        response = _response(status=status, body={"message": "SECRET BODY from the host", "errors": []})
        response.reason = reason
        session.get.return_value = response
        with pytest.raises(GitSourceError) as caught:
            provider.resolve_head()
        assert "SECRET BODY" not in str(caught.value)
        assert f"error {status}" in str(caught.value) and reason in str(caught.value)
    too_large = _response(status=403, body={"message": "SECRET too large", "errors": [{"code": "too_large"}]})
    too_large.reason = "Forbidden"
    session.get.return_value = too_large
    with pytest.raises(FileTooLargeError) as caught:
        provider.read_blob(SHA_A, path="big.bin")
    assert "SECRET" not in str(caught.value) and "Forbidden" in str(caught.value)
    plain = _response(status=502, content=b"<html>SECRET page</html>")
    plain.reason = "Bad\x00 Gateway"
    session.get.return_value = plain
    with pytest.raises(GitSourceError) as caught:
        provider.resolve_head()
    assert "SECRET" not in str(caught.value) and str(caught.value).endswith("Bad Gateway")


def test_github_errors_from_github_com_quote_the_api_message(github):
    provider, fake = github
    fake.add("/branches/main", _response(status=500, body={"message": "Server trouble"}))
    with pytest.raises(GitSourceError, match="error 500 .*: Server trouble"):
        provider.resolve_head()


@pytest.mark.parametrize("url, default", [
    (None, True), ("", True), ("https://api.github.com", True), ("https://API.github.com/", True),
    ("https://api.github.com.evil.example", False), ("https://ghe.example.com/api/v3", False),
])
def test_is_default_github_api_url(url, default):
    assert providers.is_default_github_api_url(url) is default


def test_file_too_large_error_default_message():
    error = FileTooLargeError("a.bin", 10, 5)
    assert str(error) == "a.bin (10 bytes) exceeds the 5 byte per-file limit of the provider API"
    assert isinstance(error, GitSourceError)
    assert str(FileTooLargeError(None, None, 5)).startswith("file exceeds")
