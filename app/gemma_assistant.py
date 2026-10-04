"""
Gemma AI Vault Assistant Integration for DriveVault AI.

Uses Google's open-weight Gemma model (gemma-2-9b-it) to provide a natural language
interface for managing encrypted files in Google Drive.

CRITICAL SECURITY CONSTRAINT:
Gemma handles ONLY natural language understanding and user intent classification.
Gemma NEVER performs cryptographic key derivation, encryption, or decryption operations!
"""

import json
import re
from typing import Dict, Any, Optional

from app.config import settings

class GemmaVaultAssistant:
    """Natural Language Assistant powered by Gemma open-weight AI model."""

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        self.api_key = api_key or settings.GEMMA_API_KEY
        self.model_name = model_name or settings.GEMMA_MODEL_NAME
        self.client = None

        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[GemmaAssistant] Failed to initialize GenAI client: {e}")

    def process_message(self, user_prompt: str) -> Dict[str, Any]:
        """
        Parses user prompt using Gemma AI (or rule-based parser fallback)
        and returns structured JSON intent with friendly response message.
        """
        if not user_prompt or not user_prompt.strip():
            return {
                "intent": "unknown",
                "target": None,
                "requires_confirmation": False,
                "response": "Please enter a command or ask a question about your vault."
            }

        # If GenAI Gemma client is available, call model
        if self.client:
            try:
                system_instruction = (
                    "You are DriveVault AI Assistant, powered by Gemma open-weight model. "
                    "Your job is to analyze the user's natural language request and respond ONLY in valid JSON format.\n"
                    "Do NOT perform any file encryption or decryption. Simply classify the intent.\n\n"
                    "Supported Intents:\n"
                    "- encrypt_and_upload: User wants to encrypt and upload a file. (e.g. 'Encrypt my resume')\n"
                    "- list_files: User wants to view encrypted vault files. (e.g. 'Show my encrypted files')\n"
                    "- download_file: User wants to download or decrypt a file. (e.g. 'Download resume.pdf')\n"
                    "- delete_file: User wants to delete a file. (e.g. 'Delete my old notes')\n"
                    "- explain_security: User asks about encryption, Argon2id, AES-256-GCM, or security.\n"
                    "- general: General chat or greeting.\n\n"
                    "JSON Output Format:\n"
                    "{\n"
                    '  "intent": "intent_name",\n'
                    '  "target": "target_filename_if_specified_else_null",\n'
                    '  "requires_confirmation": true_if_destructive_else_false,\n'
                    '  "response": "Helpful human readable response explaining what step to take next."\n'
                    "}"
                )

                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=f"{system_instruction}\n\nUser Request: {user_prompt}"
                )
                
                text = response.text.strip()
                # Parse JSON block from response text
                json_match = re.search(r"\{.*\}", text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(0))
            except Exception as e:
                print(f"[GemmaAssistant] LLM call failed or timed out: {e}. Falling back to rule parser.")

        # Heuristic / Rule-based parser fallback (ensures 100% offline reliability)
        return self._rule_based_parser(user_prompt)

    def _rule_based_parser(self, prompt: str) -> Dict[str, Any]:
        """Fall-back natural language intent parser."""
        lower = prompt.lower()

        # Extract potential file target (e.g. filename.ext)
        file_match = re.search(r"\b[\w\-.\[\]()]+\.(?:pdf|docx|txt|jpg|png|zip|vault|doc)\b", prompt, re.IGNORECASE)
        target = file_match.group(0).strip() if file_match else None

        if re.search(r"\b(?:list|show|view)\b.*\b(?:files|vault)\b|\bshow my\b|\bmy files\b", lower):
            return {
                "intent": "list_files",
                "target": None,
                "requires_confirmation": False,
                "response": "Here are the encrypted .vault files currently stored in your Google Drive Vault."
            }

        elif re.search(r"\b(?:delete|remove|erase)\b", lower):
            target_name = target or "the selected file"
            return {
                "intent": "delete_file",
                "target": target,
                "requires_confirmation": True,
                "response": f"Are you sure you want to permanently delete '{target_name}' from your Google Drive Vault?"
            }

        elif re.search(r"\b(?:download|decrypt|get|restore)\b", lower):
            target_str = f" for '{target}'" if target else ""
            return {
                "intent": "download_file",
                "target": target,
                "requires_confirmation": False,
                "response": f"I parsed your request to download and decrypt{target_str}. Select the file from the list and enter your password."
            }

        elif re.search(r"\b(?:encrypt|upload|secure)\b", lower):
            target_str = f" for file '{target}'" if target else ""
            return {
                "intent": "encrypt_and_upload",
                "target": target,
                "requires_confirmation": False,
                "response": f"I parsed your request to encrypt and upload{target_str}. Please select the file in the vault dropzone and enter your password."
            }

        elif re.search(r"\b(?:how|security|argon2|aes|gcm|encryption|privacy)\b", lower):
            return {
                "intent": "explain_security",
                "target": None,
                "requires_confirmation": False,
                "response": (
                    "DriveVault AI protects your files using AES-256-GCM authenticated encryption and Argon2id key derivation. "
                    "Plaintext files and passwords are never stored or uploaded. Google Drive stores ONLY your encrypted .vault packages."
                )
            }

        return {
            "intent": "general",
            "target": target,
            "requires_confirmation": False,
            "response": f"Hello! I am your Gemma Vault Assistant. I can help you encrypt files, list your vault contents, download/decrypt files, or answer security questions."
        }
