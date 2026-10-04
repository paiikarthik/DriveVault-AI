"""
Automated Gemma AI Assistant Test Suite for DriveVault AI.

Tests natural language prompt intent parsing into structured JSON schemas.
"""

from app.gemma_assistant import GemmaVaultAssistant

def test_gemma_assistant_intent_parsing():
    """Test natural language intent classification."""
    assistant = GemmaVaultAssistant()

    # Test encrypt intent
    res1 = assistant.process_message("Encrypt my resume.pdf and upload to Drive")
    assert res1["intent"] == "encrypt_and_upload"
    assert res1["target"] == "resume.pdf"

    # Test list files intent
    res2 = assistant.process_message("Show my encrypted files in the vault")
    assert res2["intent"] == "list_files"

    # Test download intent
    res3 = assistant.process_message("Download and decrypt notes.docx")
    assert res3["intent"] == "download_file"

    # Test delete intent (requires confirmation)
    res4 = assistant.process_message("Delete old_report.pdf")
    assert res4["intent"] == "delete_file"
    assert res4["requires_confirmation"] is True

    # Test security question
    res5 = assistant.process_message("How does AES-256-GCM encryption work?")
    assert res5["intent"] == "explain_security"
    assert "AES-256-GCM" in res5["response"]
