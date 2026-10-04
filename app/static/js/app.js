// DriveVault AI Interactive Frontend Script

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    if (window.lucide) {
        lucide.createIcons();
    }

    // State Variables
    let selectedEncryptFile = null;
    let selectedDecryptFile = null;
    let selectedDecryptDriveId = null;
    let fileToDeleteId = null;

    // Elements
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const driveStatusBadge = document.getElementById('drive-status-badge');
    const driveStatusText = document.getElementById('drive-status-text');
    const btnConnectDrive = document.getElementById('btn-connect-drive');

    // Encrypt Tab Elements
    const encryptDropzone = document.getElementById('encrypt-dropzone');
    const encryptFileInput = document.getElementById('encrypt-file-input');
    const selectedFileInfo = document.getElementById('selected-file-info');
    const selectedFilename = document.getElementById('selected-filename');
    const selectedFilesize = document.getElementById('selected-filesize');
    const encryptPasswordInput = document.getElementById('encrypt-password');
    const strengthBar = document.getElementById('strength-bar');
    const uploadToDriveCheck = document.getElementById('upload-to-drive-check');
    const btnEncryptUpload = document.getElementById('btn-encrypt-upload');

    // Decrypt Tab Elements
    const decryptDropzone = document.getElementById('decrypt-dropzone');
    const decryptFileInput = document.getElementById('decrypt-file-input');
    const selectedVaultInfo = document.getElementById('selected-vault-info');
    const selectedVaultFilename = document.getElementById('selected-vault-filename');
    const decryptPasswordInput = document.getElementById('decrypt-password');
    const btnDecryptFile = document.getElementById('btn-decrypt-file');

    // Shared Status Box
    const statusBox = document.getElementById('status-box');
    const statusIcon = document.getElementById('status-icon');
    const statusMessage = document.getElementById('status-message');

    // Vault Files Table
    const btnRefreshFiles = document.getElementById('btn-refresh-files');
    const vaultFilesBody = document.getElementById('vault-files-body');

    // Gemma Chat Elements
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatMessages = document.getElementById('chat-messages');

    // Confirmation Modal Elements
    const confirmModal = document.getElementById('confirm-modal');
    const modalBody = document.getElementById('modal-body');
    const modalBtnCancel = document.getElementById('modal-btn-cancel');
    const modalBtnConfirm = document.getElementById('modal-btn-confirm');

    // Tab Navigation
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
            hideStatus();
        });
    });

    // Toggle Password Visibility
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '<i data-lucide="eye-off"></i>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<i data-lucide="eye"></i>';
            }
            if (window.lucide) lucide.createIcons();
        });
    });

    // Password Strength Meter
    encryptPasswordInput.addEventListener('input', (e) => {
        const val = e.target.value;
        let score = 0;
        if (val.length >= 8) score += 25;
        if (/[A-Z]/.test(val)) score += 25;
        if (/[0-9]/.test(val)) score += 25;
        if (/[^A-Za-z0-9]/.test(val)) score += 25;

        strengthBar.style.width = `${score}%`;
        if (score <= 25) {
            strengthBar.style.background = 'var(--accent-danger)';
        } else if (score <= 75) {
            strengthBar.style.background = 'var(--accent-gold)';
        } else {
            strengthBar.style.background = 'var(--accent-green)';
        }
    });

    // Drag and Drop Handling - Encrypt
    encryptFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleEncryptFileSelect(e.target.files[0]);
        }
    });

    function handleEncryptFileSelect(file) {
        selectedEncryptFile = file;
        selectedFilename.textContent = file.name;
        selectedFilesize.textContent = formatBytes(file.size);
        selectedFileInfo.classList.remove('hidden');
    }

    // Drag and Drop Handling - Decrypt
    decryptFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleDecryptFileSelect(e.target.files[0]);
        }
    });

    function handleDecryptFileSelect(file) {
        selectedDecryptFile = file;
        selectedDecryptDriveId = null;
        btnDecryptFile.removeAttribute('data-target-fileid');
        selectedVaultFilename.textContent = file.name;
        selectedVaultInfo.classList.remove('hidden');
    }

    // Check Drive Connection Status
    async function checkDriveStatus() {
        try {
            const res = await fetch('/api/drive/status');
            const data = await res.json();
            if (data.connected) {
                driveStatusBadge.className = 'badge badge-online';
                driveStatusText.textContent = 'Google Drive Connected';
                btnConnectDrive.style.display = 'none';
            } else {
                driveStatusBadge.className = 'badge badge-offline';
                driveStatusText.textContent = 'Local Vault Mode';
                btnConnectDrive.style.display = 'inline-flex';
            }
        } catch (err) {
            console.error('Failed to check drive status', err);
        }
    }

    // Connect Google Drive Button
    btnConnectDrive.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/drive/auth-url');
            const data = await res.json();
            if (data.configured && data.auth_url) {
                window.location.href = data.auth_url;
            } else {
                showStatus(data.message || 'Google OAuth credentials not configured in server environment.', 'error');
            }
        } catch (err) {
            showStatus('Error starting Google OAuth flow.', 'error');
        }
    });

    // Encrypt & Upload Action
    btnEncryptUpload.addEventListener('click', async () => {
        if (!selectedEncryptFile) {
            showStatus('Please select a file to encrypt.', 'error');
            return;
        }
        const password = encryptPasswordInput.value;
        if (!password) {
            showStatus('Please enter a master password to encrypt your file.', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('file', selectedEncryptFile);
        formData.append('password', password);
        formData.append('upload_to_drive', uploadToDriveCheck.checked);

        showStatus('Encrypting locally using AES-256-GCM + Argon2id...', 'success');
        btnEncryptUpload.disabled = true;

        try {
            const res = await fetch('/api/vault/encrypt', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (res.ok && data.success) {
                showStatus(data.message, 'success');
                encryptPasswordInput.value = '';
                strengthBar.style.width = '0%';
                loadVaultFiles();
            } else {
                showStatus(data.detail || 'Encryption failed.', 'error');
            }
        } catch (err) {
            showStatus('Network or server error during encryption.', 'error');
        } finally {
            btnEncryptUpload.disabled = false;
        }
    });

    // Decrypt Action
    btnDecryptFile.addEventListener('click', async () => {
        const password = decryptPasswordInput.value;
        if (!password) {
            showStatus('Please enter your vault password.', 'error');
            return;
        }

        const formData = new FormData();
        const targetFileId = selectedDecryptDriveId || btnDecryptFile.getAttribute('data-target-fileid');

        if (selectedDecryptFile) {
            formData.append('file', selectedDecryptFile);
        } else if (targetFileId) {
            formData.append('file_id', targetFileId);
        } else {
            showStatus('Please select a .vault file or select one from the Drive table.', 'error');
            return;
        }
        formData.append('password', password);

        showStatus('Verifying AES-GCM tag & deriving key with Argon2id...', 'success');
        btnDecryptFile.disabled = true;

        try {
            const res = await fetch('/api/vault/decrypt', {
                method: 'POST',
                body: formData
            });

            if (res.ok) {
                const blob = await res.blob();
                const disposition = res.headers.get('Content-Disposition');
                let filename = 'decrypted_file';
                if (disposition && disposition.includes('filename=')) {
                    filename = disposition.split('filename=')[1].replace(/"/g, '');
                }

                // Trigger direct file download in browser
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);

                showStatus(`Successfully decrypted and restored exact original file: '${filename}'`, 'success');
                decryptPasswordInput.value = '';
                btnDecryptFile.removeAttribute('data-target-fileid');
                selectedDecryptFile = null;
                selectedVaultInfo.classList.add('hidden');
            } else {
                const errData = await res.json();
                showStatus(errData.detail || 'Decryption failed. Incorrect password or modified file.', 'error');
            }
        } catch (err) {
            showStatus('Decryption failed. The password may be incorrect or the file may have been modified.', 'error');
        } finally {
            btnDecryptFile.disabled = false;
        }
    });

    // Fetch and Load Vault Files Table
    async function loadVaultFiles() {
        vaultFilesBody.innerHTML = '<tr><td colspan="3" class="empty-state">Loading vault files...</td></tr>';
        try {
            const res = await fetch('/api/drive/files');
            const data = await res.json();
            if (data.success && data.files && data.files.length > 0) {
                vaultFilesBody.innerHTML = '';
                data.files.forEach(f => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>
                            <i data-lucide="shield-check" style="vertical-align: middle; color: var(--accent-cyan);"></i>
                            <strong>${escapeHtml(f.name)}</strong>
                        </td>
                        <td>${formatBytes(f.size)}</td>
                        <td>
                            <button class="btn btn-sm btn-secondary btn-decrypt-table" data-id="${f.id}" data-name="${escapeHtml(f.name)}">
                                <i data-lucide="download"></i> Decrypt
                            </button>
                            <button class="btn btn-sm btn-danger btn-delete-table" data-id="${f.id}" data-name="${escapeHtml(f.name)}">
                                <i data-lucide="trash-2"></i>
                            </button>
                        </td>
                    `;
                    vaultFilesBody.appendChild(tr);
                });
                if (window.lucide) lucide.createIcons();
                attachTableActionListeners();
            } else {
                vaultFilesBody.innerHTML = '<tr><td colspan="3" class="empty-state">No encrypted .vault files found.</td></tr>';
            }
        } catch (err) {
            vaultFilesBody.innerHTML = '<tr><td colspan="3" class="empty-state">Failed to load files.</td></tr>';
        }
    }

    btnRefreshFiles.addEventListener('click', loadVaultFiles);

    function attachTableActionListeners() {
        document.querySelectorAll('.btn-decrypt-table').forEach(btn => {
            btn.addEventListener('click', () => {
                const fileId = btn.getAttribute('data-id');
                const fileName = btn.getAttribute('data-name');
                selectedDecryptFile = null;
                selectedDecryptDriveId = fileId;
                // Switch to Decrypt tab & populate
                document.querySelector('.tab-btn[data-tab="decrypt-tab"]').click();
                selectedVaultFilename.textContent = `${fileName} (Cloud Vault ID: ${fileId.substring(0, 8)}...)`;
                selectedVaultInfo.classList.remove('hidden');
                // Set custom attribute for direct file ID decryption
                btnDecryptFile.setAttribute('data-target-fileid', fileId);
            });
        });

        document.querySelectorAll('.btn-delete-table').forEach(btn => {
            btn.addEventListener('click', () => {
                fileToDeleteId = btn.getAttribute('data-id');
                const fileName = btn.getAttribute('data-name');
                modalBody.textContent = `Are you sure you want to permanently delete '${fileName}' from your vault storage?`;
                confirmModal.classList.remove('hidden');
            });
        });
    }

    // Modal Action Listeners
    modalBtnCancel.addEventListener('click', () => {
        confirmModal.classList.add('hidden');
        fileToDeleteId = null;
    });

    modalBtnConfirm.addEventListener('click', async () => {
        if (!fileToDeleteId) return;
        confirmModal.classList.add('hidden');
        try {
            const res = await fetch(`/api/drive/files/${fileToDeleteId}`, {
                method: 'DELETE'
            });
            const data = await res.json();
            if (res.ok) {
                showStatus('File deleted successfully.', 'success');
                loadVaultFiles();
            } else {
                showStatus('Failed to delete file.', 'error');
            }
        } catch (err) {
            showStatus('Error deleting file.', 'error');
        } finally {
            fileToDeleteId = null;
        }
    });

    // Gemma AI Assistant Chat
    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const msg = chatInput.value.trim();
        if (!msg) return;

        appendChatBubble(msg, 'user');
        chatInput.value = '';

        try {
            const res = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message: msg})
            });
            const data = await res.json();
            appendChatBubble(data.response, 'bot');

            // Handle parsed intent actions
            if (data.intent === 'list_files') {
                loadVaultFiles();
            } else if (data.intent === 'encrypt_and_upload') {
                document.querySelector('.tab-btn[data-tab="encrypt-tab"]').click();
            } else if (data.intent === 'download_file') {
                document.querySelector('.tab-btn[data-tab="decrypt-tab"]').click();
            }
        } catch (err) {
            appendChatBubble("Sorry, I encountered an error communicating with Gemma assistant.", 'bot');
        }
    });

    function appendChatBubble(text, sender) {
        const bubble = document.createElement('div');
        bubble.className = `chat-bubble ${sender}-bubble`;
        bubble.textContent = text;
        chatMessages.appendChild(bubble);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Status Message Helper
    function showStatus(msg, type) {
        statusBox.className = `status-box ${type}`;
        statusMessage.textContent = msg;
        statusBox.classList.remove('hidden');
    }

    function hideStatus() {
        statusBox.classList.add('hidden');
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function escapeHtml(str) {
        return str.replace(/[&<>"']/g, function(m) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[m];
        });
    }

    // Initial Loads
    checkDriveStatus();
    loadVaultFiles();
});
