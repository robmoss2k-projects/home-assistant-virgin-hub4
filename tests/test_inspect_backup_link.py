"""Metadata-only backup link inspection never follows or exposes the link."""

from tools.inspect_backup_link import summarize_link


def test_reports_structure_without_filename_or_query_values():
    result = summarize_link(
        "http://192.168.0.1:80/backup/guest-private-configuration.cfg?token=not-for-logs",
        "192.168.0.1",
    )
    assert result == {
        "form": "absolute",
        "scheme": "http",
        "same_host": True,
        "explicit_port": 80,
        "directory_shape": ["backup"],
        "leaf_suffix": ".cfg",
        "php_handler": None,
        "matches_exact_backup_path": False,
        "query_present": True,
        "query_parameters": [{"name": "token", "shape": "opaque"}],
        "nonce_matches_session": None,
        "fragment_present": False,
        "userinfo_present": False,
    }
    assert "not-for-logs" not in str(result)


def test_reports_php_handler_and_parameter_shapes_without_their_values():
    result = summarize_link(
        "php/exampleDownload.php?file=%2Fprivate%2Frouter-id.cfg&nonce=123456&mode=",
        "192.168.0.1",
    )
    assert result["php_handler"] == "/php/exampleDownload.php"
    assert result["query_parameters"] == [
        {"name": "file", "shape": "path.cfg"},
        {"name": "nonce", "shape": "decimal"},
        {"name": "mode", "shape": "empty"},
    ]
    assert "router-id" not in str(result)
    assert "123456" not in str(result)


def test_reports_dotted_php_name_and_only_whether_nonce_matches():
    nonce = "private-nonce-value"
    result = summarize_link(
        f"php/1.backup.config.php?HTTP_CSRF_NONCE={nonce}",
        "192.168.0.1",
        session_nonce=nonce,
    )
    assert result["php_handler"] == "/php/1.backup.config.php"
    assert result["nonce_matches_session"] is True
    assert nonce not in str(result)
