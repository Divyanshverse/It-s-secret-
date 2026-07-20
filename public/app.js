// Initialize Lucide icons
lucide.createIcons();

// DOM Elements
const setupOverlay = document.getElementById('setup-overlay');
const loginOverlay = document.getElementById('login-overlay');
const appContainer = document.getElementById('app-container');

const btnTheme = document.getElementById('btn-theme');
const btnLogout = document.getElementById('btn-logout');
const btnUpload = document.getElementById('btn-upload');
const btnNewFolder = document.getElementById('btn-new-folder');
const btnBulkDelete = document.getElementById('btn-bulk-delete');
const btnBulkDownload = document.getElementById('btn-bulk-download');
const fileInput = document.getElementById('file-input');
const dropZone = document.getElementById('drop-zone');
const fileList = document.getElementById('file-list');
const emptyState = document.getElementById('empty-state');
const breadcrumbsEl = document.getElementById('breadcrumbs');

const storageUsedEl = document.getElementById('storage-used');
const storageTotalEl = document.getElementById('storage-total');
const storageProgressEl = document.getElementById('storage-progress');

// State
let token = localStorage.getItem('vault_token') || null;
let currentFolderId = 'root';
let breadcrumbPath = [{ id: 'root', name: 'Root' }];
let cachedManifest = null;
let selectedItems = new Set();
const TOTAL_STORAGE = 5 * 1024 * 1024 * 1024; // 5 GB

// Initialization
async function checkStatus() {
  try {
    const res = await fetch('/api/status');
    const status = await res.json();
    
    if (!status.setupComplete) {
      setupOverlay.classList.remove('hidden');
    } else if (status.locked || !token) {
      loginOverlay.classList.remove('hidden');
    } else {
      showApp();
    }
  } catch (err) {
    console.error('Failed to connect to server', err);
  }
}

// Setup
document.getElementById('btn-setup').addEventListener('click', async () => {
  const pwd = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-confirm').value;
  const errEl = document.getElementById('setup-error');
  
  if (pwd !== confirm) {
    errEl.textContent = 'Passwords do not match';
    return;
  }
  if (pwd.length < 12) {
    errEl.textContent = 'Password must be at least 12 characters';
    return;
  }
  
  errEl.textContent = 'Initializing vault (this may take a moment)...';
  
  try {
    const res = await fetch('/api/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd })
    });
    
    const data = await res.json();
    if (data.success) {
      setupOverlay.classList.add('hidden');
      loginOverlay.classList.remove('hidden');
      errEl.textContent = '';
    } else {
      errEl.textContent = data.error;
    }
  } catch (err) {
    errEl.textContent = 'Network error';
  }
});

// Login
document.getElementById('btn-login').addEventListener('click', async () => {
  const pwd = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  
  errEl.textContent = 'Unlocking vault...';
  
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd })
    });
    
    const data = await res.json();
    if (data.token) {
      token = data.token;
      localStorage.setItem('vault_token', token);
      loginOverlay.classList.add('hidden');
      document.getElementById('login-password').value = '';
      errEl.textContent = '';
      showApp();
    } else {
      errEl.textContent = data.error;
    }
  } catch (err) {
    errEl.textContent = 'Network error';
  }
});

// Logout
btnLogout.addEventListener('click', async () => {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
  } catch (e) {}
  
  token = null;
  localStorage.removeItem('vault_token');
  appContainer.classList.add('hidden');
  loginOverlay.classList.remove('hidden');
});

// Theme Toggle
btnTheme.addEventListener('click', () => {
  document.body.classList.toggle('dark-theme');
  const isDark = document.body.classList.contains('dark-theme');
  btnTheme.innerHTML = `<i data-lucide="${isDark ? 'sun' : 'moon'}"></i>`;
  lucide.createIcons();
});

// App Logic
function showApp() {
  appContainer.classList.remove('hidden');
  loadFiles();
}

async function fetchAPI(endpoint, options = {}) {
  options.headers = options.headers || {};
  options.headers['Authorization'] = `Bearer ${token}`;
  
  const res = await fetch(endpoint, options);
  if (res.status === 401) {
    token = null;
    localStorage.removeItem('vault_token');
    appContainer.classList.add('hidden');
    loginOverlay.classList.remove('hidden');
    throw new Error('Unauthorized');
  }
  return res;
}

async function loadFiles() {
  try {
    const res = await fetchAPI('/api/files');
    cachedManifest = await res.json();
    
    updateStorage(cachedManifest.root);
    renderBreadcrumbs();
    
    const currentFolder = findFolder(cachedManifest.root, currentFolderId);
    if (!currentFolder) {
      currentFolderId = 'root';
      breadcrumbPath = [{ id: 'root', name: 'Root' }];
      loadFiles();
      return;
    }
    
    selectedItems.clear();
    updateBulkActions();
    renderFiles(currentFolder);
  } catch (err) {
    console.error(err);
  }
}

function findFolder(folder, id) {
  if (folder.id === id) return folder;
  for (const key in folder.folders) {
    const found = findFolder(folder.folders[key], id);
    if (found) return found;
  }
  return null;
}

function calculateSize(folder) {
  let size = 0;
  folder.files.forEach(f => size += f.size);
  for (const key in folder.folders) {
    size += calculateSize(folder.folders[key]);
  }
  return size;
}

function updateStorage(rootFolder) {
  const used = calculateSize(rootFolder);
  storageUsedEl.textContent = formatSize(used);
  storageTotalEl.textContent = formatSize(TOTAL_STORAGE);
  const pct = Math.min((used / TOTAL_STORAGE) * 100, 100);
  storageProgressEl.style.width = `${pct}%`;
  storageProgressEl.style.backgroundColor = pct > 90 ? 'var(--danger)' : 'var(--primary)';
}

function renderBreadcrumbs() {
  breadcrumbsEl.innerHTML = '';
  const homeIcon = document.createElement('i');
  homeIcon.setAttribute('data-lucide', 'home');
  breadcrumbsEl.appendChild(homeIcon);
  
  breadcrumbPath.forEach((crumb, index) => {
    const isLast = index === breadcrumbPath.length - 1;
    const span = document.createElement('span');
    span.textContent = index === 0 ? ' / Root' : ` / ${crumb.name}`;
    if (!isLast) {
      span.addEventListener('click', () => {
        breadcrumbPath = breadcrumbPath.slice(0, index + 1);
        currentFolderId = crumb.id;
        loadFiles();
      });
    }
    breadcrumbsEl.appendChild(span);
  });
  lucide.createIcons();
}

function updateBulkActions() {
  if (selectedItems.size > 0) {
    btnBulkDelete.classList.remove('hidden');
    btnBulkDownload.classList.remove('hidden');
  } else {
    btnBulkDelete.classList.add('hidden');
    btnBulkDownload.classList.add('hidden');
  }
}

function renderFiles(folder) {
  fileList.innerHTML = '';
  const folders = Object.values(folder.folders || {});
  const files = folder.files || [];
  
  if (folders.length === 0 && files.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');
    
    // Render Folders
    folders.forEach(f => {
      const el = document.createElement('div');
      el.className = 'file-item';
      
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.className = 'file-checkbox';
      chk.checked = selectedItems.has(f.id);
      chk.addEventListener('change', (e) => {
        if (e.target.checked) selectedItems.add(f.id);
        else selectedItems.delete(f.id);
        updateBulkActions();
      });
      
      el.innerHTML = `
        <div class="file-icon"><i data-lucide="folder" class="text-blue"></i></div>
        <div class="file-info" style="cursor:pointer;" onclick="navigateToFolder('${f.id}', '${f.name}')">
          <div class="file-name">${f.name}</div>
          <div class="file-meta">Folder</div>
        </div>
        <div class="file-actions">
          <button class="icon-btn btn-delete" data-id="${f.id}" title="Delete"><i data-lucide="trash-2"></i></button>
        </div>
      `;
      el.prepend(chk);
      fileList.appendChild(el);
    });

    // Render Files
    files.forEach(file => {
      const el = document.createElement('div');
      el.className = 'file-item';
      
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.className = 'file-checkbox';
      chk.checked = selectedItems.has(file.id);
      chk.addEventListener('change', (e) => {
        if (e.target.checked) selectedItems.add(file.id);
        else selectedItems.delete(file.id);
        updateBulkActions();
      });
      
      const icon = file.type.startsWith('image') ? 'image' : 
                   file.type.startsWith('video') ? 'video' : 
                   file.type.startsWith('audio') ? 'music' : 'file';
                   
      const date = new Date(file.createdAt).toLocaleString();
      
      el.innerHTML = `
        <div class="file-icon"><i data-lucide="${icon}"></i></div>
        <div class="file-info" style="cursor:pointer;" onclick="downloadFile('${file.id}')">
          <div class="file-name">${file.name}</div>
          <div class="file-meta">${formatSize(file.size)} &bull; ${date}</div>
        </div>
        <div class="file-actions">
          <button class="icon-btn btn-download" data-id="${file.id}" title="Download"><i data-lucide="download"></i></button>
          <button class="icon-btn btn-delete" data-id="${file.id}" title="Delete"><i data-lucide="trash-2"></i></button>
        </div>
      `;
      el.prepend(chk);
      fileList.appendChild(el);
    });
    
    lucide.createIcons();
    
    // Attach events
    document.querySelectorAll('.btn-download').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); downloadFile(btn.dataset.id); });
    });
    document.querySelectorAll('.btn-delete').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); deleteFile(btn.dataset.id); });
    });
  }
}

window.navigateToFolder = function(id, name) {
  currentFolderId = id;
  breadcrumbPath.push({ id, name });
  loadFiles();
};

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function uploadFiles(files) {
  for (let i = 0; i < files.length; i++) {
    const formData = new FormData();
    formData.append('file', files[i]);
    formData.append('folderId', currentFolderId);
    
    try {
      await fetchAPI('/api/files/upload', {
        method: 'POST',
        body: formData
      });
    } catch (e) {
      console.error('Upload failed', e);
    }
  }
  loadFiles();
}

async function deleteFile(id) {
  if (confirm('Delete this file? It cannot be recovered.')) {
    await fetchAPI(`/api/files/${id}`, { method: 'DELETE' });
    loadFiles();
  }
}

async function downloadFile(id) {
  try {
    const res = await fetchAPI('/api/files/download-ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileId: id })
    });
    const data = await res.json();
    if (data.ticket) {
      // Create temporary link to download
      const a = document.createElement('a');
      a.href = `/api/files/download/${data.ticket}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  } catch (err) {
    console.error('Download failed', err);
  }
}

// Drag and drop
btnUpload.addEventListener('click', () => fileInput.click());
btnNewFolder.addEventListener('click', async () => {
  const name = prompt('New Folder Name:');
  if (name) {
    try {
      await fetchAPI('/api/folders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ parentId: currentFolderId, name })
      });
      loadFiles();
    } catch (e) {
      console.error('Failed to create folder', e);
    }
  }
});

btnBulkDelete.addEventListener('click', async () => {
  if (confirm(`Delete ${selectedItems.size} items?`)) {
    for (const id of selectedItems) {
      try {
        await fetchAPI(`/api/files/${id}`, { method: 'DELETE' });
      } catch (e) {}
    }
    selectedItems.clear();
    loadFiles();
  }
});

function collectFilesForZip(folder, targetIds, basePath = "", filesToZip = []) {
  if (targetIds.has(folder.id)) {
    // If the folder itself is selected, collect EVERYTHING inside it recursively
    folder.files.forEach(f => filesToZip.push({ id: f.id, path: basePath + f.name }));
    for (const k in folder.folders) {
      collectFilesForZip(folder.folders[k], new Set([folder.folders[k].id]), basePath + folder.folders[k].name + "/", filesToZip);
    }
  } else {
    // Check its children
    folder.files.forEach(f => {
      if (targetIds.has(f.id)) filesToZip.push({ id: f.id, path: basePath + f.name });
    });
    for (const k in folder.folders) {
      collectFilesForZip(folder.folders[k], targetIds, basePath + folder.folders[k].name + "/", filesToZip);
    }
  }
  return filesToZip;
}

btnBulkDownload.addEventListener('click', async () => {
  if (!window.JSZip) {
    alert("JSZip library not loaded.");
    return;
  }
  btnBulkDownload.disabled = true;
  btnBulkDownload.innerHTML = `<i data-lucide="loader"></i> Zipping...`;
  lucide.createIcons();
  
  try {
    const zip = new JSZip();
    const filesToZip = collectFilesForZip(cachedManifest.root, selectedItems);
    
    for (const f of filesToZip) {
      const res = await fetchAPI('/api/files/download-ticket', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fileId: f.id })
      });
      const data = await res.json();
      if (data.ticket) {
        const streamRes = await fetch(`/api/files/download/${data.ticket}`);
        const blob = await streamRes.blob();
        zip.file(f.path, blob);
      }
    }
    
    const zipBlob = await zip.generateAsync({ type: "blob" });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(zipBlob);
    a.download = `Vault_Export_${new Date().getTime()}.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } catch (err) {
    console.error('Bulk download failed', err);
    alert('Bulk download failed.');
  } finally {
    btnBulkDownload.disabled = false;
    btnBulkDownload.innerHTML = `<i data-lucide="download-cloud"></i> Bulk Download`;
    selectedItems.clear();
    loadFiles();
  }
});

fileInput.addEventListener('change', (e) => uploadFiles(e.target.files));

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) {
    uploadFiles(e.dataTransfer.files);
  }
});

// Boot
checkStatus();
