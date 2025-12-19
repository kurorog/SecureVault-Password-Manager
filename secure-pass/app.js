// SecurePass - Менеджер паролей с локальным шифрованием

// ======================
// 1. УТИЛИТЫ ШИФРОВАНИЯ
// ======================

class EncryptionUtils {
    static async encrypt(text, password) {
        try {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                new TextEncoder().encode(text)
            );
            
            const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(new Uint8Array(encrypted), salt.length + iv.length);
            
            return btoa(String.fromCharCode.apply(null, combined));
        } catch (error) {
            console.error('Ошибка шифрования:', error);
            throw new Error('Не удалось зашифровать данные');
        }
    }

    static async decrypt(encryptedText, password) {
        try {
            const binary = atob(encryptedText);
            const combined = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                combined[i] = binary.charCodeAt(i);
            }
            
            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const encrypted = combined.slice(28);
            
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                encrypted
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Ошибка расшифровки:', error);
            throw new Error('Неверный мастер-пароль или поврежденные данные');
        }
    }

    static generatePassword(length = 12, options = {
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: false
    }) {
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        let chars = '';
        if (options.uppercase) chars += uppercase;
        if (options.lowercase) chars += lowercase;
        if (options.numbers) chars += numbers;
        if (options.symbols) chars += symbols;
        
        if (!chars) chars = uppercase + lowercase + numbers;
        
        let password = '';
        const randomValues = new Uint32Array(length);
        crypto.getRandomValues(randomValues);
        
        for (let i = 0; i < length; i++) {
            password += chars[randomValues[i] % chars.length];
        }
        
        return password;
    }

    static async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

// ======================
// 2. БАЗА ДАННЫХ
// ======================

class PasswordDatabase {
    constructor() {
        this.db = null;
        this.masterPassword = null;
        this.currentPasswordId = null;
        this.isEditing = false;
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('SecurePassDB', 1);
            
            request.onerror = () => reject(request.error);
            
            request.onsuccess = () => {
                this.db = request.result;
                console.log('База данных инициализирована');
                resolve();
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                if (!db.objectStoreNames.contains('passwords')) {
                    const store = db.createObjectStore('passwords', { keyPath: 'id' });
                    store.createIndex('title', 'title', { unique: false });
                    store.createIndex('createdAt', 'createdAt', { unique: false });
                }
                
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings', { keyPath: 'key' });
                }
            };
        });
    }

    setMasterPassword(password) {
        this.masterPassword = password;
    }

    async savePassword(passwordData) {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('База данных не инициализирована'));
            if (!this.masterPassword) return reject(new Error('Мастер-пароль не установлен'));

            const transaction = this.db.transaction(['passwords'], 'readwrite');
            const store = transaction.objectStore('passwords');

            const passwordWithId = {
                ...passwordData,
                id: passwordData.id || Date.now().toString() + Math.random().toString(36).substr(2, 9),
                createdAt: passwordData.createdAt || new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            const request = store.put(passwordWithId);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                console.log('Пароль сохранен:', passwordWithId.id);
                resolve(passwordWithId.id);
            };
        });
    }

    async getPasswords() {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('База данных не инициализирована'));

            const transaction = this.db.transaction(['passwords'], 'readonly');
            const store = transaction.objectStore('passwords');
            const request = store.getAll();

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                const passwords = request.result || [];
                passwords.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                resolve(passwords);
            };
        });
    }

    async getPassword(id) {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('База данных не инициализирована'));

            const transaction = this.db.transaction(['passwords'], 'readonly');
            const store = transaction.objectStore('passwords');
            const request = store.get(id);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async deletePassword(id) {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('База данных не инициализирована'));

            const transaction = this.db.transaction(['passwords'], 'readwrite');
            const store = transaction.objectStore('passwords');
            const request = store.delete(id);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                console.log('Пароль удален:', id);
                resolve();
            };
        });
    }

    async searchPasswords(query) {
        const passwords = await this.getPasswords();
        const lowercaseQuery = query.toLowerCase();
        
        return passwords.filter(password => {
            return (
                password.title.toLowerCase().includes(lowercaseQuery) ||
                password.username.toLowerCase().includes(lowercaseQuery) ||
                (password.url && password.url.toLowerCase().includes(lowercaseQuery)) ||
                (password.notes && password.notes.toLowerCase().includes(lowercaseQuery))
            );
        });
    }

    async saveSetting(key, value) {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('База данных не инициализирована'));

            const transaction = this.db.transaction(['settings'], 'readwrite');
            const store = transaction.objectStore('settings');
            const request = store.put({ key, value, updatedAt: new Date().toISOString() });

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }

    async getSetting(key) {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('База данных не инициализирована'));

            const transaction = this.db.transaction(['settings'], 'readonly');
            const store = transaction.objectStore('settings');
            const request = store.get(key);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result ? request.result.value : null);
        });
    }

    async exportData() {
        const passwords = await this.getPasswords();
        
        return {
            version: '1.0',
            exportDate: new Date().toISOString(),
            passwords: passwords,
            itemCount: passwords.length
        };
    }

    async importData(data) {
        if (!data.passwords || !Array.isArray(data.passwords)) {
            throw new Error('Некорректный формат данных');
        }

        const transaction = this.db.transaction(['passwords'], 'readwrite');
        const store = transaction.objectStore('passwords');

        for (const password of data.passwords) {
            await new Promise((resolve, reject) => {
                const request = store.put(password);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }
    }
}

// ======================
// 3. ГЛАВНОЕ ПРИЛОЖЕНИЕ
// ======================

class SecurePassApp {
    constructor() {
        this.db = new PasswordDatabase();
        this.init();
    }

    async init() {
        try {
            await this.db.init();
            console.log('SecurePass приложение загружено');
            
            // Обновляем счетчик паролей
            this.updatePasswordCount();
        } catch (error) {
            console.error('Ошибка инициализации:', error);
            this.showNotification('Ошибка инициализации базы данных', 'error');
        }
    }

    // АВТОРИЗАЦИЯ
    async handleLogin() {
        const masterPassword = document.getElementById('master-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const isRegisterMode = document.getElementById('confirm-group').style.display !== 'none';

        if (!masterPassword) {
            this.showNotification('Введите мастер-пароль', 'error');
            return;
        }

        if (isRegisterMode) {
            // РЕГИСТРАЦИЯ
            if (masterPassword !== confirmPassword) {
                this.showNotification('Пароли не совпадают', 'error');
                return;
            }

            if (masterPassword.length < 8) {
                this.showNotification('Пароль должен быть не менее 8 символов', 'error');
                return;
            }

            try {
                const passwordHash = await EncryptionUtils.hashPassword(masterPassword);
                await this.db.saveSetting('masterPasswordHash', passwordHash);
                await this.db.saveSetting('appInitialized', true);
                this.db.setMasterPassword(masterPassword);
                
                this.showNotification('Хранилище создано успешно!', 'success');
                this.switchToMainScreen();
                this.loadPasswords();
            } catch (error) {
                console.error('Ошибка регистрации:', error);
                this.showNotification('Ошибка при создании хранилища', 'error');
            }
        } else {
            // ВХОД
            try {
                const savedHash = await this.db.getSetting('masterPasswordHash');
                
                if (!savedHash) {
                    this.showNotification('Сначала создайте хранилище', 'error');
                    this.toggleRegister();
                    return;
                }

                const inputHash = await EncryptionUtils.hashPassword(masterPassword);
                
                if (inputHash === savedHash) {
                    this.db.setMasterPassword(masterPassword);
                    this.showNotification('Успешный вход!', 'success');
                    this.switchToMainScreen();
                    this.loadPasswords();
                } else {
                    this.showNotification('Неверный мастер-пароль', 'error');
                }
            } catch (error) {
                console.error('Ошибка входа:', error);
                this.showNotification('Ошибка входа', 'error');
            }
        }
    }

    toggleRegister() {
        const confirmGroup = document.getElementById('confirm-group');
        const loginBtn = document.getElementById('login-btn');
        const registerBtn = document.getElementById('register-btn');

        if (confirmGroup.style.display === 'none') {
            confirmGroup.style.display = 'block';
            loginBtn.style.display = 'none';
            registerBtn.textContent = 'Создать хранилище';
            registerBtn.classList.remove('btn-secondary');
            registerBtn.classList.add('btn-primary');
        } else {
            confirmGroup.style.display = 'none';
            loginBtn.style.display = 'block';
            registerBtn.textContent = 'Создать новое хранилище';
            registerBtn.classList.remove('btn-primary');
            registerBtn.classList.add('btn-secondary');
        }
    }

    // РАБОТА С ПАРОЛЯМИ
    async loadPasswords() {
        try {
            const passwords = await this.db.getPasswords();
            const passwordList = document.getElementById('password-list');
            const emptyState = document.getElementById('empty-state');
            const passwordForm = document.getElementById('password-form');

            if (passwords.length === 0) {
                passwordList.innerHTML = '';
                emptyState.style.display = 'block';
                passwordForm.style.display = 'none';
                this.updatePasswordCount();
                return;
            }

            emptyState.style.display = 'none';
            this.updatePasswordCount();

            let html = '';
            passwords.forEach(password => {
                const escapedTitle = this.escapeHtml(password.title || 'Без названия');
                const escapedUsername = this.escapeHtml(password.username || 'Нет логина');
                const escapedUrl = password.url ? this.escapeHtml(password.url) : '';
                
                html += `
                    <div class="password-item" data-id="${password.id}">
                        <div class="password-info">
                            <h4>${escapedTitle}</h4>
                            <p>${escapedUsername}</p>
                            ${escapedUrl ? `<small>${escapedUrl}</small>` : ''}
                        </div>
                        <div class="password-actions">
                            <button onclick="app.copyPassword('${password.id}')" title="Копировать пароль">
                                📋
                            </button>
                            <button onclick="app.editPassword('${password.id}')" title="Редактировать">
                                ✏️
                            </button>
                            <button class="delete-btn" onclick="app.deletePassword('${password.id}')" title="Удалить">
                                🗑️
                            </button>
                        </div>
                    </div>
                `;
            });

            passwordList.innerHTML = html;
        } catch (error) {
            console.error('Ошибка загрузки паролей:', error);
            this.showNotification('Ошибка загрузки паролей', 'error');
        }
    }

    showAddForm(editId = null) {
        const passwordForm = document.getElementById('password-form');
        const formTitle = document.getElementById('form-title');
        const saveBtn = document.getElementById('save-btn');
        const emptyState = document.getElementById('empty-state');

        if (editId) {
            this.db.isEditing = true;
            this.db.currentPasswordId = editId;
            formTitle.textContent = 'Редактировать пароль';
            saveBtn.textContent = 'Сохранить изменения';
            this.loadPasswordForEdit(editId);
        } else {
            this.db.isEditing = false;
            this.db.currentPasswordId = null;
            formTitle.textContent = 'Добавить пароль';
            saveBtn.textContent = 'Сохранить';
            this.clearPasswordForm();
        }

        passwordForm.style.display = 'block';
        emptyState.style.display = 'none';
    }

    async loadPasswordForEdit(id) {
        try {
            const password = await this.db.getPassword(id);
            if (!password) return;

            document.getElementById('password-title').value = password.title || '';
            document.getElementById('password-username').value = password.username || '';
            document.getElementById('password-value').value = password.password || '';
            document.getElementById('password-url').value = password.url || '';
            document.getElementById('password-notes').value = password.notes || '';
        } catch (error) {
            console.error('Ошибка загрузки пароля:', error);
        }
    }

    hideAddForm() {
        document.getElementById('password-form').style.display = 'none';
        this.db.isEditing = false;
        this.db.currentPasswordId = null;
        this.clearPasswordForm();
    }

    clearPasswordForm() {
        document.getElementById('password-title').value = '';
        document.getElementById('password-username').value = '';
        document.getElementById('password-value').value = '';
        document.getElementById('password-url').value = '';
        document.getElementById('password-notes').value = '';
    }

    async savePassword() {
        const title = document.getElementById('password-title').value.trim();
        const username = document.getElementById('password-username').value.trim();
        const passwordValue = document.getElementById('password-value').value;
        const url = document.getElementById('password-url').value.trim();
        const notes = document.getElementById('password-notes').value.trim();

        if (!title) {
            this.showNotification('Введите название', 'error');
            return;
        }

        if (!passwordValue) {
            this.showNotification('Введите пароль', 'error');
            return;
        }

        try {
            const passwordData = {
                title,
                username,
                password: passwordValue,
                url: url || undefined,
                notes: notes || undefined,
                category: 'general'
            };

            if (this.db.isEditing && this.db.currentPasswordId) {
                passwordData.id = this.db.currentPasswordId;
            }

            await this.db.savePassword(passwordData);
            this.showNotification('Пароль сохранен', 'success');
            this.hideAddForm();
            this.loadPasswords();
        } catch (error) {
            console.error('Ошибка сохранения пароля:', error);
            this.showNotification('Ошибка сохранения', 'error');
        }
    }

    async deletePassword(id) {
        if (!confirm('Вы уверены, что хотите удалить этот пароль?')) return;

        try {
            await this.db.deletePassword(id);
            this.showNotification('Пароль удален', 'success');
            this.loadPasswords();
        } catch (error) {
            console.error('Ошибка удаления пароля:', error);
            this.showNotification('Ошибка удаления', 'error');
        }
    }

    async copyPassword(id) {
        try {
            const password = await this.db.getPassword(id);
            if (!password || !password.password) return;

            await navigator.clipboard.writeText(password.password);
            this.showNotification('Пароль скопирован в буфер обмена', 'success');
        } catch (error) {
            console.error('Ошибка копирования:', error);
            this.showNotification('Ошибка копирования', 'error');
        }
    }

    editPassword(id) {
        this.showAddForm(id);
    }

    // ПОИСК
    async searchPasswords() {
        const query = document.getElementById('search-input').value.trim();
        if (!query) {
            this.loadPasswords();
            return;
        }

        try {
            const results = await this.db.searchPasswords(query);
            const passwordList = document.getElementById('password-list');
            const emptyState = document.getElementById('empty-state');

            if (results.length === 0) {
                passwordList.innerHTML = '';
                emptyState.style.display = 'block';
                emptyState.innerHTML = `
                    <div class="empty-icon">🔍</div>
                    <h3>Ничего не найдено</h3>
                    <p>Попробуйте другой запрос</p>
                `;
                return;
            }

            emptyState.style.display = 'none';

            let html = '';
            results.forEach(password => {
                const escapedTitle = this.escapeHtml(password.title);
                const escapedUsername = this.escapeHtml(password.username || 'Нет логина');
                
                html += `
                    <div class="password-item" data-id="${password.id}">
                        <div class="password-info">
                            <h4>${escapedTitle}</h4>
                            <p>${escapedUsername}</p>
                        </div>
                        <div class="password-actions">
                            <button onclick="app.copyPassword('${password.id}')" title="Копировать пароль">
                                📋
                            </button>
                            <button onclick="app.editPassword('${password.id}')" title="Редактировать">
                                ✏️
                            </button>
                        </div>
                    </div>
                `;
            });

            passwordList.innerHTML = html;
        } catch (error) {
            console.error('Ошибка поиска:', error);
        }
    }

    // ГЕНЕРАТОР ПАРОЛЕЙ
    generatePassword() {
        document.getElementById('generator-modal').style.display = 'flex';
        this.generateNewPassword();
    }

    generateNewPassword() {
        const length = parseInt(document.getElementById('password-length').value);
        const useUppercase = document.getElementById('use-uppercase').checked;
        const useLowercase = document.getElementById('use-lowercase').checked;
        const useNumbers = document.getElementById('use-numbers').checked;
        const useSymbols = document.getElementById('use-symbols').checked;

        const password = EncryptionUtils.generatePassword(length, {
            uppercase: useUppercase,
            lowercase: useLowercase,
            numbers: useNumbers,
            symbols: useSymbols
        });

        document.getElementById('generated-password').value = password;
    }

    copyGeneratedPassword() {
        const passwordField = document.getElementById('generated-password');
        passwordField.select();
        document.execCommand('copy');
        
        this.showNotification('Пароль скопирован', 'success');
        document.getElementById('password-value').value = passwordField.value;
        this.hideGenerator();
    }

    generateRandomPassword() {
        const password = EncryptionUtils.generatePassword(16, {
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: false
        });
        
        document.getElementById('password-value').value = password;
    }

    hideGenerator() {
        document.getElementById('generator-modal').style.display = 'none';
    }

    // ЭКСПОРТ/ИМПОРТ
    async exportData() {
        try {
            const data = await this.db.exportData();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `securepass-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            this.showNotification('Данные экспортированы', 'success');
        } catch (error) {
            console.error('Ошибка экспорта:', error);
            this.showNotification('Ошибка экспорта', 'error');
        }
    }

    async importData() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
            try {
                const text = await file.text();
                const data = JSON.parse(text);
                
                if (!data.passwords || !Array.isArray(data.passwords)) {
                    throw new Error('Некорректный формат файла');
                }
                
                await this.db.importData(data);
                this.showNotification('Данные импортированы', 'success');
                this.loadPasswords();
            } catch (error) {
                console.error('Ошибка импорта:', error);
                this.showNotification('Ошибка импорта данных', 'error');
            }
        };
        
        input.click();
    }

    // ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
    switchToMainScreen() {
        document.getElementById('auth-screen').classList.remove('active');
        document.getElementById('main-screen').classList.add('active');
    }

    logout() {
        if (confirm('Вы уверены, что хотите выйти? Все несохраненные данные будут потеряны.')) {
            this.db.setMasterPassword(null);
            document.getElementById('auth-screen').classList.add('active');
            document.getElementById('main-screen').classList.remove('active');
            document.getElementById('master-password').value = '';
            document.getElementById('confirm-password').value = '';
            this.toggleRegister();
            this.hideAddForm();
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.getElementById('notification');
        notification.textContent = message;
        
        const colors = {
            success: '#48bb78',
            error: '#f56565',
            info: '#4299e1',
            warning: '#ed8936'
        };
        
        notification.style.background = colors[type] || colors.info;
        notification.style.display = 'block';
        
        setTimeout(() => {
            notification.style.display = 'none';
        }, 3000);
    }

    async updatePasswordCount() {
        try {
            const passwords = await this.db.getPasswords();
            const count = passwords.length;
            document.getElementById('password-count').textContent = `${count} паролей`;
        } catch (error) {
            document.getElementById('password-count').textContent = '0 паролей';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// ======================
// ИНИЦИАЛИЗАЦИЯ
// ======================

// Глобальный объект приложения
const app = new SecurePassApp();

// Глобальные функции для HTML
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}

function handleLogin() {
    app.handleLogin();
}

function toggleRegister() {
    app.toggleRegister();
}

function showAddForm() {
    app.showAddForm();
}

function hideAddForm() {
    app.hideAddForm();
}

function savePassword() {
    app.savePassword();
}

function generatePassword() {
    app.generatePassword();
}

function generateNewPassword() {
    app.generateNewPassword();
}

function copyGeneratedPassword() {
    app.copyGeneratedPassword();
}

function hideGenerator() {
    app.hideGenerator();
}

function generateRandomPassword() {
    app.generateRandomPassword();
}

function searchPasswords() {
    app.searchPasswords();
}

function exportData() {
    app.exportData();
}

function importData() {
    app.importData();
}

function logout() {
    app.logout();
}

// Делаем app глобально доступным
window.app = app;