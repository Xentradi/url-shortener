(() => {
  const root = document.getElementById('adminConsole');
  if (!root) return;

  const csrfToken = String(root.dataset.csrfToken || '').trim();
  const globalStatusEl = document.getElementById('adminGlobalStatus');
  const jsonOutputEl = document.getElementById('adminJsonOutput');

  const urlState = {
    total: 0,
    limit: 50,
    offset: 0,
    lastQuery: '',
  };

  const auditState = {
    total: 0,
    limit: 100,
    offset: 0,
    lastQuery: '',
  };

  initTabs();
  bindOverview();
  bindApiKeys();
  bindUrls();
  bindMaintenance();
  bindAudit();

  void refreshStats();
  void loadRecentUrls();
  void loadApiKeys();

  function initTabs() {
    const tabs = Array.from(document.querySelectorAll('[data-admin-tab]'));
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const tabName = tab.getAttribute('data-admin-tab');
        if (!tabName) return;
        tabs.forEach((candidate) => {
          candidate.classList.toggle('is-active', candidate === tab);
        });
        document.querySelectorAll('[data-admin-panel]').forEach((panel) => {
          panel.classList.toggle('is-active', panel.getAttribute('data-admin-panel') === tabName);
        });
        if (tabName === 'audit' && !auditState.lastQuery) {
          void loadAuditPage(0);
        }
      });
    });
  }

  function bindOverview() {
    const statsBtn = document.getElementById('adminRefreshStatsBtn');
    const refreshUrlsBtn = document.getElementById('adminOverviewRefreshUrlsBtn');
    if (statsBtn) {
      statsBtn.addEventListener('click', () => {
        void refreshStats();
      });
    }
    if (refreshUrlsBtn) {
      refreshUrlsBtn.addEventListener('click', () => {
        void loadRecentUrls();
      });
    }
  }

  function bindApiKeys() {
    const createForm = document.getElementById('adminApiKeyCreateForm');
    const updateForm = document.getElementById('adminApiKeyUpdateForm');
    const refreshBtn = document.getElementById('adminApiKeysRefreshBtn');
    const rotateSelectedBtn = document.getElementById('adminApiKeyRotateSelectedBtn');
    const deleteSelectedBtn = document.getElementById('adminApiKeyDeleteSelectedBtn');
    const tableBody = document.getElementById('adminApiKeysBody');

    if (createForm) {
      createForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const name = readTrimmed(form, 'name');
        if (!name) {
          setStatus('adminApiKeyStatus', 'error', 'API key name is required.');
          return;
        }
        const scopesRaw = readTrimmed(form, 'scopes');
        const payload = {name};
        const scopes = parseScopes(scopesRaw);
        if (scopesRaw) {
          payload.scopes = scopes;
        }

        try {
          const result = await requestJson('/admin/api-keys', {
            method: 'POST',
            body: payload,
          });
          setStatus('adminApiKeyStatus', 'success', 'API key created.');
          showJson('Created API key', result);
          form.reset();
          await loadApiKeys();
        } catch (error) {
          handleError('adminApiKeyStatus', 'Failed to create API key', error);
        }
      });
    }

    if (updateForm) {
      updateForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const id = readTrimmed(form, 'id');
        if (!id) {
          setStatus('adminApiKeyStatus', 'error', 'API key ID is required.');
          return;
        }

        const payload = {};
        const name = readTrimmed(form, 'name');
        if (name) payload.name = name;
        const scopesRaw = readTrimmed(form, 'scopes');
        if (scopesRaw) payload.scopes = parseScopes(scopesRaw);
        const activeRaw = readTrimmed(form, 'active');
        if (activeRaw === 'true') payload.active = true;
        if (activeRaw === 'false') payload.active = false;

        if (Object.keys(payload).length === 0) {
          setStatus('adminApiKeyStatus', 'error', 'Add at least one field to update.');
          return;
        }

        try {
          const result = await requestJson(`/admin/api-keys/${encodeURIComponent(id)}`, {
            method: 'PATCH',
            body: payload,
          });
          setStatus('adminApiKeyStatus', 'success', 'API key updated.');
          showJson('Updated API key', result);
          await loadApiKeys();
        } catch (error) {
          handleError('adminApiKeyStatus', 'Failed to update API key', error);
        }
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        void loadApiKeys();
      });
    }

    if (rotateSelectedBtn) {
      rotateSelectedBtn.addEventListener('click', () => {
        const id = getSelectedApiKeyId();
        if (!id) {
          setStatus('adminApiKeyStatus', 'error', 'Select or enter an API key ID first.');
          return;
        }
        if (!window.confirm(`Rotate API key ${id}?`)) return;
        void rotateApiKey(id);
      });
    }

    if (deleteSelectedBtn) {
      deleteSelectedBtn.addEventListener('click', () => {
        const id = getSelectedApiKeyId();
        if (!id) {
          setStatus('adminApiKeyStatus', 'error', 'Select or enter an API key ID first.');
          return;
        }
        if (!window.confirm(`Delete API key ${id}?`)) return;
        void deleteApiKey(id);
      });
    }

    if (tableBody) {
      tableBody.addEventListener('click', (event) => {
        const button = event.target.closest('[data-key-action]');
        if (!button) return;
        const action = button.getAttribute('data-key-action');
        const id = String(button.getAttribute('data-key-id') || '').trim();
        if (!id) return;

        if (action === 'fill') {
          fillApiKeyUpdateForm({
            id,
            name: String(button.getAttribute('data-key-name') || ''),
            scopes: String(button.getAttribute('data-key-scopes') || ''),
            active: String(button.getAttribute('data-key-active') || ''),
          });
          setStatus('adminApiKeyStatus', 'info', `Loaded API key ${id} into the edit form.`);
          return;
        }

        if (action === 'rotate') {
          if (!window.confirm(`Rotate API key ${id}?`)) return;
          void rotateApiKey(id);
          return;
        }

        if (action === 'delete') {
          if (!window.confirm(`Delete API key ${id}?`)) return;
          void deleteApiKey(id);
        }
      });
    }
  }

  async function loadApiKeys() {
    try {
      const keys = await requestJson('/admin/api-keys');
      const tableBody = document.getElementById('adminApiKeysBody');
      if (tableBody) {
        if (!Array.isArray(keys) || keys.length === 0) {
          tableBody.innerHTML = '<tr><td colspan="7" class="ui-muted">No API keys found.</td></tr>';
        } else {
          tableBody.innerHTML = keys.map((key) => renderApiKeyRow(key)).join('');
        }
      }
      setStatus('adminApiKeyStatus', 'success', `Loaded ${Array.isArray(keys) ? keys.length : 0} API keys.`);
      showJson('API keys', keys);
    } catch (error) {
      handleError('adminApiKeyStatus', 'Failed to load API keys', error);
    }
  }

  async function rotateApiKey(id) {
    try {
      const result = await requestJson(`/admin/api-keys/${encodeURIComponent(id)}/rotate`, {
        method: 'POST',
      });
      setStatus('adminApiKeyStatus', 'success', `API key ${id} rotated.`);
      showJson('Rotated API key', result);
      await loadApiKeys();
    } catch (error) {
      handleError('adminApiKeyStatus', `Failed to rotate API key ${id}`, error);
    }
  }

  async function deleteApiKey(id) {
    try {
      await requestJson(`/admin/api-keys/${encodeURIComponent(id)}`, {method: 'DELETE'});
      setStatus('adminApiKeyStatus', 'success', `API key ${id} deleted.`);
      showJson('Deleted API key', {id, deleted: true});
      await loadApiKeys();
    } catch (error) {
      handleError('adminApiKeyStatus', `Failed to delete API key ${id}`, error);
    }
  }

  function getSelectedApiKeyId() {
    const input = document.getElementById('adminApiKeyUpdateId');
    return input ? String(input.value || '').trim() : '';
  }

  function fillApiKeyUpdateForm({id, name, scopes, active}) {
    setValue('adminApiKeyUpdateId', id);
    setValue('adminApiKeyUpdateName', name);
    setValue('adminApiKeyUpdateScopes', scopes);
    const activeInput = document.getElementById('adminApiKeyUpdateActive');
    if (activeInput) {
      activeInput.value = active === 'true' ? 'true' : active === 'false' ? 'false' : '';
    }
  }

  function bindUrls() {
    const refreshBtn = document.getElementById('adminUrlsRefreshBtn');
    const searchForm = document.getElementById('adminUrlSearchForm');
    const lookupIdForm = document.getElementById('adminUrlLookupIdForm');
    const lookupShortForm = document.getElementById('adminUrlLookupShortForm');
    const updateForm = document.getElementById('adminUrlUpdateForm');
    const deleteBtn = document.getElementById('adminUrlDeleteSelectedBtn');
    const prevBtn = document.getElementById('adminUrlsPrevBtn');
    const nextBtn = document.getElementById('adminUrlsNextBtn');

    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        void loadUrlsPage(urlState.offset);
      });
    }

    if (searchForm) {
      searchForm.addEventListener('submit', (event) => {
        event.preventDefault();
        void loadUrlsPage(0);
      });
    }

    if (lookupIdForm) {
      lookupIdForm.addEventListener('submit', (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const id = readTrimmed(form, 'id');
        if (!id) {
          setStatus('adminUrlStatus', 'error', 'URL ID is required.');
          return;
        }
        const includeDeleted = Boolean(form.querySelector('input[name="includeDeleted"]')?.checked);
        void fetchUrlById(id, includeDeleted);
      });
    }

    if (lookupShortForm) {
      lookupShortForm.addEventListener('submit', (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const shortId = readTrimmed(form, 'shortId');
        if (!shortId) {
          setStatus('adminUrlStatus', 'error', 'Short ID is required.');
          return;
        }
        const includeDeleted = Boolean(form.querySelector('input[name="includeDeleted"]')?.checked);
        void fetchUrlByShortId(shortId, includeDeleted);
      });
    }

    if (updateForm) {
      updateForm.addEventListener('submit', (event) => {
        event.preventDefault();
        void updateUrlRecord();
      });
    }

    if (deleteBtn) {
      deleteBtn.addEventListener('click', () => {
        const id = readTrimmed(updateForm, 'id');
        if (!id) {
          setStatus('adminUrlStatus', 'error', 'Choose a URL first.');
          return;
        }
        if (!window.confirm(`Soft delete URL ${id}?`)) return;
        void deleteUrlRecord(id);
      });
    }

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        const nextOffset = Math.max(urlState.offset - urlState.limit, 0);
        void loadUrlsPage(nextOffset);
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        const nextOffset = urlState.offset + urlState.limit;
        if (nextOffset >= urlState.total) return;
        void loadUrlsPage(nextOffset);
      });
    }

    const recentBody = document.getElementById('adminRecentUrlsBody');
    const urlsBody = document.getElementById('adminUrlsBody');
    [recentBody, urlsBody].forEach((body) => {
      if (!body) return;
      body.addEventListener('click', (event) => {
        const button = event.target.closest('[data-url-action]');
        if (!button) return;
        const action = button.getAttribute('data-url-action');
        const id = String(button.getAttribute('data-url-id') || '').trim();
        const shortId = String(button.getAttribute('data-url-short-id') || '').trim();
        if (!id) return;

        if (action === 'inspect') {
          void fetchUrlById(id, true);
          return;
        }
        if (action === 'fill') {
          setValue('adminUrlUpdateId', id);
          if (shortId) setValue('adminUrlLookupShortId', shortId);
          setStatus('adminUrlStatus', 'info', `Loaded URL ${id} into the edit form.`);
          return;
        }
        if (action === 'delete') {
          if (!window.confirm(`Soft delete URL ${id}?`)) return;
          void deleteUrlRecord(id);
        }
      });
    });
  }

  function buildUrlQuery(offset) {
    const form = document.getElementById('adminUrlSearchForm');
    if (!form) return new URLSearchParams();
    const params = new URLSearchParams();
    const formData = new FormData(form);
    for (const [key, value] of formData.entries()) {
      const normalized = String(value || '').trim();
      if (!normalized) continue;
      if (key === 'includeDeleted') {
        params.set(key, 'true');
      } else {
        params.set(key, normalized);
      }
    }

    const parsedLimit = clampInt(params.get('limit'), 50, 1, 200);
    const parsedOffset = clampInt(params.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER);
    params.set('limit', String(parsedLimit));
    params.set('offset', String(offset === undefined ? parsedOffset : offset));
    return params;
  }

  async function loadUrlsPage(offset) {
    const params = buildUrlQuery(offset);
    urlState.lastQuery = params.toString();
    try {
      const result = await requestJson(`/admin/urls?${params.toString()}`);
      renderUrlTable(result);
      setStatus('adminUrlStatus', 'success', `Loaded ${result.items.length} URLs.`);
      showJson('URL search', result);
    } catch (error) {
      handleError('adminUrlStatus', 'Failed to load URLs', error);
    }
  }

  function renderUrlTable(result) {
    const tableBody = document.getElementById('adminUrlsBody');
    if (!tableBody) return;

    const items = Array.isArray(result?.items) ? result.items : [];
    if (items.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="8" class="ui-muted">No URLs found for this query.</td></tr>';
    } else {
      tableBody.innerHTML = items.map((item) => renderUrlRow(item)).join('');
    }

    urlState.total = Number(result?.total || 0);
    urlState.limit = Number(result?.limit || 50);
    urlState.offset = Number(result?.offset || 0);
    setValue('adminUrlOffset', String(urlState.offset));

    const pageInfo = document.getElementById('adminUrlsPageInfo');
    if (pageInfo) {
      if (urlState.total === 0) {
        pageInfo.textContent = 'No URL records match this query.';
      } else {
        const from = urlState.offset + 1;
        const to = Math.min(urlState.offset + items.length, urlState.total);
        pageInfo.textContent = `Showing ${from}-${to} of ${urlState.total}.`;
      }
    }

    const prevBtn = document.getElementById('adminUrlsPrevBtn');
    const nextBtn = document.getElementById('adminUrlsNextBtn');
    if (prevBtn) prevBtn.disabled = urlState.offset <= 0;
    if (nextBtn) nextBtn.disabled = urlState.offset + urlState.limit >= urlState.total;
  }

  async function fetchUrlById(id, includeDeleted) {
    const query = includeDeleted ? '?includeDeleted=true' : '';
    try {
      const record = await requestJson(`/admin/urls/${encodeURIComponent(id)}${query}`);
      fillUrlUpdateForm(record);
      setStatus('adminUrlStatus', 'success', `Loaded URL ${id}.`);
      showJson('URL by ID', record);
    } catch (error) {
      handleError('adminUrlStatus', `Failed to fetch URL ${id}`, error);
    }
  }

  async function fetchUrlByShortId(shortId, includeDeleted) {
    const query = includeDeleted ? '?includeDeleted=true' : '';
    try {
      const record = await requestJson(`/admin/urls/by-short-id/${encodeURIComponent(shortId)}${query}`);
      fillUrlUpdateForm(record);
      setStatus('adminUrlStatus', 'success', `Loaded short ID ${shortId}.`);
      showJson('URL by short ID', record);
    } catch (error) {
      handleError('adminUrlStatus', `Failed to fetch short ID ${shortId}`, error);
    }
  }

  function fillUrlUpdateForm(record) {
    if (!record || typeof record !== 'object') return;
    setValue('adminUrlUpdateId', String(record._id || ''));
    setValue('adminUrlUpdateOriginalUrl', String(record.originalUrl || ''));
    setValue('adminUrlUpdateExpirationDate', record.expirationDate ? String(record.expirationDate) : '');
    setCheckbox('adminUrlUpdateClearExpiration', false);
    setValue('adminUrlUpdateClicks', record.clicks === undefined ? '' : String(record.clicks));
    setValue('adminUrlUpdateLastClickAt', record.lastClickAt ? String(record.lastClickAt) : '');
    setCheckbox('adminUrlUpdateClearLastClickAt', false);
    setValue('adminUrlUpdateApiKeyId', record.apiKeyId ? String(record.apiKeyId) : '');
    setCheckbox('adminUrlUpdateClearApiKeyId', false);
  }

  async function updateUrlRecord() {
    const form = document.getElementById('adminUrlUpdateForm');
    if (!form) return;

    const id = readTrimmed(form, 'id');
    if (!id) {
      setStatus('adminUrlStatus', 'error', 'URL ID is required.');
      return;
    }

    const payload = {};
    const originalUrl = readTrimmed(form, 'originalUrl');
    if (originalUrl) payload.originalUrl = originalUrl;

    const clearExpiration = Boolean(form.querySelector('input[name="clearExpiration"]')?.checked);
    const expirationDate = readTrimmed(form, 'expirationDate');
    if (clearExpiration) {
      payload.expirationDate = null;
    } else if (expirationDate) {
      payload.expirationDate = expirationDate;
    }

    const clicksRaw = readTrimmed(form, 'clicks');
    if (clicksRaw) payload.clicks = Number(clicksRaw);

    const clearLastClickAt = Boolean(form.querySelector('input[name="clearLastClickAt"]')?.checked);
    const lastClickAt = readTrimmed(form, 'lastClickAt');
    if (clearLastClickAt) {
      payload.lastClickAt = null;
    } else if (lastClickAt) {
      payload.lastClickAt = lastClickAt;
    }

    const clearApiKeyId = Boolean(form.querySelector('input[name="clearApiKeyId"]')?.checked);
    const apiKeyId = readTrimmed(form, 'apiKeyId');
    if (clearApiKeyId) {
      payload.apiKeyId = null;
    } else if (apiKeyId) {
      payload.apiKeyId = apiKeyId;
    }

    if (Object.keys(payload).length === 0) {
      setStatus('adminUrlStatus', 'error', 'Add at least one field to update.');
      return;
    }

    try {
      const result = await requestJson(`/admin/urls/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: payload,
      });
      fillUrlUpdateForm(result);
      setStatus('adminUrlStatus', 'success', `Updated URL ${id}.`);
      showJson('Updated URL', result);
      await Promise.all([loadRecentUrls(), loadUrlsPage(urlState.offset), refreshStats()]);
    } catch (error) {
      handleError('adminUrlStatus', `Failed to update URL ${id}`, error);
    }
  }

  async function deleteUrlRecord(id) {
    try {
      await requestJson(`/admin/urls/${encodeURIComponent(id)}`, {method: 'DELETE'});
      setStatus('adminUrlStatus', 'success', `Soft deleted URL ${id}.`);
      showJson('Soft deleted URL', {id, deleted: true});
      await Promise.all([loadRecentUrls(), loadUrlsPage(urlState.offset), refreshStats()]);
    } catch (error) {
      handleError('adminUrlStatus', `Failed to delete URL ${id}`, error);
    }
  }

  function bindMaintenance() {
    const refreshBtn = document.getElementById('adminMaintenanceRefreshStatsBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        void refreshStats();
      });
    }

    document.querySelectorAll('.ui-maint-form').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const endpoint = String(form.getAttribute('data-endpoint') || '').trim();
        if (!endpoint) return;
        const payload = collectFormPayload(form);
        try {
          const result = await requestJson(endpoint, {
            method: 'POST',
            body: payload,
          });
          setStatus('adminMaintenanceStatus', 'success', `Maintenance job completed: ${endpoint}`);
          showJson(`Maintenance result: ${endpoint}`, result);
          await Promise.all([refreshStats(), loadRecentUrls(), loadUrlsPage(urlState.offset)]);
        } catch (error) {
          handleError('adminMaintenanceStatus', `Maintenance job failed: ${endpoint}`, error);
        }
      });
    });

    const nukeForm = document.getElementById('adminNukeForm');
    if (nukeForm) {
      nukeForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const nukeKey = readTrimmed(nukeForm, 'nukeKey');
        const confirmToken = readTrimmed(nukeForm, 'confirm');
        const alsoApiKeys = Boolean(nukeForm.querySelector('input[name="alsoApiKeys"]')?.checked);

        if (!nukeKey) {
          setStatus('adminMaintenanceStatus', 'error', 'Admin nuke key is required.');
          return;
        }
        if (confirmToken !== 'WIPE-ALL') {
          setStatus('adminMaintenanceStatus', 'error', 'Confirm token must be exactly WIPE-ALL.');
          return;
        }
        if (!window.confirm('This will permanently delete all URLs. Continue?')) return;

        try {
          const result = await requestJson('/admin/maintenance/nuke', {
            method: 'POST',
            headers: {'x-admin-nuke-key': nukeKey},
            body: {
              confirm: confirmToken,
              alsoApiKeys,
            },
          });
          setStatus('adminMaintenanceStatus', 'success', 'Nuke operation completed.');
          showJson('Nuke result', result);
          await Promise.all([refreshStats(), loadRecentUrls(), loadApiKeys(), loadUrlsPage(0), loadAuditPage(0)]);
        } catch (error) {
          handleError('adminMaintenanceStatus', 'Nuke operation failed', error);
        }
      });
    }
  }

  function bindAudit() {
    const form = document.getElementById('adminAuditForm');
    const refreshBtn = document.getElementById('adminAuditRefreshBtn');
    const prevBtn = document.getElementById('adminAuditPrevBtn');
    const nextBtn = document.getElementById('adminAuditNextBtn');

    if (form) {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        void loadAuditPage(0);
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        void loadAuditPage(auditState.offset);
      });
    }

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        const nextOffset = Math.max(auditState.offset - auditState.limit, 0);
        void loadAuditPage(nextOffset);
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        const nextOffset = auditState.offset + auditState.limit;
        if (nextOffset >= auditState.total) return;
        void loadAuditPage(nextOffset);
      });
    }
  }

  function buildAuditQuery(offset) {
    const form = document.getElementById('adminAuditForm');
    if (!form) return new URLSearchParams();
    const params = new URLSearchParams();
    const formData = new FormData(form);
    for (const [key, value] of formData.entries()) {
      const normalized = String(value || '').trim();
      if (!normalized) continue;
      params.set(key, normalized);
    }

    const limit = clampInt(params.get('limit'), 100, 1, 500);
    params.set('limit', String(limit));
    params.set('offset', String(offset === undefined ? 0 : offset));
    return params;
  }

  async function loadAuditPage(offset) {
    const params = buildAuditQuery(offset);
    auditState.lastQuery = params.toString();
    try {
      const result = await requestJson(`/admin/audit?${params.toString()}`);
      renderAuditTable(result);
      setStatus('adminAuditStatus', 'success', `Loaded ${result.items.length} audit records.`);
      showJson('Audit logs', result);
    } catch (error) {
      handleError('adminAuditStatus', 'Failed to load audit logs', error);
    }
  }

  function renderAuditTable(result) {
    const tableBody = document.getElementById('adminAuditBody');
    if (!tableBody) return;

    const items = Array.isArray(result?.items) ? result.items : [];
    if (items.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="7" class="ui-muted">No audit entries found.</td></tr>';
    } else {
      tableBody.innerHTML = items.map((item) => {
        return `<tr>
          <td>${escapeHtml(formatDate(item.createdAt))}</td>
          <td>${escapeHtml(item.action || '—')}</td>
          <td>${escapeHtml(item.method || '—')}</td>
          <td class="ui-break">${escapeHtml(item.path || '—')}</td>
          <td>${escapeHtml(String(item.status || '—'))}</td>
          <td>${escapeHtml(item.ip || '—')}</td>
          <td class="ui-break">${escapeHtml(item.requestId || '—')}</td>
        </tr>`;
      }).join('');
    }

    auditState.total = Number(result?.total || 0);
    auditState.limit = Number(result?.limit || 100);
    auditState.offset = Number(result?.offset || 0);

    const pageInfo = document.getElementById('adminAuditPageInfo');
    if (pageInfo) {
      if (auditState.total === 0) {
        pageInfo.textContent = 'No audit data.';
      } else {
        const from = auditState.offset + 1;
        const to = Math.min(auditState.offset + items.length, auditState.total);
        pageInfo.textContent = `Showing ${from}-${to} of ${auditState.total}.`;
      }
    }

    const prevBtn = document.getElementById('adminAuditPrevBtn');
    const nextBtn = document.getElementById('adminAuditNextBtn');
    if (prevBtn) prevBtn.disabled = auditState.offset <= 0;
    if (nextBtn) nextBtn.disabled = auditState.offset + auditState.limit >= auditState.total;
  }

  async function refreshStats() {
    try {
      const stats = await requestJson('/admin/maintenance/stats');
      setText('adminStatTotal', String(stats.total || 0));
      setText('adminStatActive', String(stats.active || 0));
      setText('adminStatExpired', String(stats.expired || 0));
      setText('adminStatDeleted', String(stats.deleted || 0));
      setText('adminStatLongTtl', String(stats.longTtl || 0));
      setText('adminStatPurgeScheduled', String(stats.purgeScheduled || 0));
      setStatus('adminOverviewStatus', 'success', 'Stats refreshed.');
      setStatus('adminGlobalStatus', 'success', 'Admin stats synchronized.');
      showJson('Maintenance stats', stats);
    } catch (error) {
      handleError('adminOverviewStatus', 'Failed to refresh maintenance stats', error);
      handleError('adminGlobalStatus', 'Stats refresh failed', error, {alsoJson: false});
    }
  }

  async function loadRecentUrls() {
    try {
      const result = await requestJson('/admin/urls?limit=20&offset=0&sortBy=createdAt&sortDir=desc&includeDeleted=true');
      const items = Array.isArray(result?.items) ? result.items : [];
      const tableBody = document.getElementById('adminRecentUrlsBody');
      if (tableBody) {
        if (items.length === 0) {
          tableBody.innerHTML = '<tr><td colspan="8" class="ui-muted">No URL records found.</td></tr>';
        } else {
          tableBody.innerHTML = items.map((item) => renderUrlRow(item)).join('');
        }
      }
      setStatus('adminOverviewStatus', 'success', `Loaded ${items.length} recent URLs.`);
      showJson('Recent URLs', result);
    } catch (error) {
      handleError('adminOverviewStatus', 'Failed to load recent URLs', error);
    }
  }

  function renderApiKeyRow(key) {
    const id = String(key?._id || '');
    const name = String(key?.name || '');
    const scopes = Array.isArray(key?.scopes) ? key.scopes.join(', ') : '';
    const active = Boolean(key?.active);
    return `<tr>
      <td class="ui-break">${escapeHtml(id)}</td>
      <td>${escapeHtml(name)}</td>
      <td class="ui-break">${escapeHtml(scopes)}</td>
      <td>${escapeHtml(active ? 'yes' : 'no')}</td>
      <td>${escapeHtml(formatDate(key?.lastUsedAt))}</td>
      <td>${escapeHtml(String(key?.usageCount || 0))}</td>
      <td class="ui-row-actions">
        <button type="button" class="ui-btn-small ui-btn-secondary" data-key-action="fill" data-key-id="${escapeHtml(id)}" data-key-name="${escapeHtml(name)}" data-key-scopes="${escapeHtml(scopes)}" data-key-active="${active ? 'true' : 'false'}">Edit</button>
        <button type="button" class="ui-btn-small ui-btn-secondary" data-key-action="rotate" data-key-id="${escapeHtml(id)}">Rotate</button>
        <button type="button" class="ui-btn-small ui-btn-danger" data-key-action="delete" data-key-id="${escapeHtml(id)}">Delete</button>
      </td>
    </tr>`;
  }

  function renderUrlRow(item) {
    const id = String(item?._id || '');
    const shortId = String(item?.shortId || '');
    const shortUrl = shortId ? `/${encodeURIComponent(shortId)}` : '';
    return `<tr>
      <td class="ui-break">${escapeHtml(id)}</td>
      <td>${shortId ? `<a href="${shortUrl}" target="_blank" rel="noopener">${escapeHtml(shortId)}</a>` : '—'}</td>
      <td class="ui-break">${escapeHtml(String(item?.originalUrl || ''))}</td>
      <td>${escapeHtml(item?.expirationDate ? formatDate(item.expirationDate) : 'Indefinite')}</td>
      <td>${escapeHtml(item?.deletedAt ? formatDate(item.deletedAt) : '—')}</td>
      <td>${escapeHtml(String(item?.clicks || 0))}</td>
      <td>${escapeHtml(item?.apiKeyId ? String(item.apiKeyId) : '—')}</td>
      <td class="ui-row-actions">
        <button type="button" class="ui-btn-small ui-btn-secondary" data-url-action="inspect" data-url-id="${escapeHtml(id)}">Inspect</button>
        <button type="button" class="ui-btn-small ui-btn-secondary" data-url-action="fill" data-url-id="${escapeHtml(id)}" data-url-short-id="${escapeHtml(shortId)}">Edit</button>
        <button type="button" class="ui-btn-small ui-btn-danger" data-url-action="delete" data-url-id="${escapeHtml(id)}">Delete</button>
      </td>
    </tr>`;
  }

  function collectFormPayload(form) {
    const payload = {};
    const fields = form.querySelectorAll('input, select, textarea');
    fields.forEach((field) => {
      const name = field.getAttribute('name');
      if (!name) return;
      if (field.type === 'checkbox') {
        payload[name] = Boolean(field.checked);
        return;
      }
      const value = String(field.value || '').trim();
      if (value === '') return;
      if (field.type === 'number') {
        payload[name] = Number(value);
      } else {
        payload[name] = value;
      }
    });
    return payload;
  }

  function parseScopes(value) {
    if (!value) return [];
    return String(value)
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean);
  }

  function readTrimmed(form, fieldName) {
    if (!form) return '';
    const field = form.elements ? form.elements[fieldName] : null;
    if (!field) return '';
    return String(field.value || '').trim();
  }

  function setValue(id, value) {
    const input = document.getElementById(id);
    if (input) input.value = value;
  }

  function setCheckbox(id, checked) {
    const input = document.getElementById(id);
    if (input && input.type === 'checkbox') {
      input.checked = Boolean(checked);
    }
  }

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function setStatus(id, type, message) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = message || '';
    el.classList.remove('is-error', 'is-success', 'is-info');
    if (!message) return;
    if (type === 'error') {
      el.classList.add('is-error');
    } else if (type === 'success') {
      el.classList.add('is-success');
    } else {
      el.classList.add('is-info');
    }
  }

  function showJson(label, data) {
    if (!jsonOutputEl) return;
    const header = label ? `${label}\n` : '';
    jsonOutputEl.textContent = `${header}${safeJson(data)}`;
  }

  function safeJson(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  function handleError(statusId, context, error, {alsoJson = true} = {}) {
    const message = normalizeErrorMessage(error);
    setStatus(statusId, 'error', `${context}: ${message}`);
    setStatus('adminGlobalStatus', 'error', `${context}: ${message}`);
    if (alsoJson) {
      showJson(`${context} (error)`, {
        error: message,
      });
    }
  }

  function normalizeErrorMessage(error) {
    if (!error) return 'Unknown error';
    if (typeof error === 'string') return error;
    if (error.message) return error.message;
    return 'Unknown error';
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  }

  function clampInt(value, fallback, min, max) {
    const parsed = Number.parseInt(String(value || ''), 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(Math.max(parsed, min), max);
  }

  async function requestJson(path, {method = 'GET', body, headers = {}} = {}) {
    const normalizedMethod = String(method || 'GET').toUpperCase();
    const requestHeaders = {
      Accept: 'application/json',
      ...headers,
    };

    if (normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD' && normalizedMethod !== 'OPTIONS' && csrfToken) {
      requestHeaders['x-ui-csrf-token'] = csrfToken;
    }

    const options = {
      method: normalizedMethod,
      headers: requestHeaders,
      credentials: 'same-origin',
    };

    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    const response = await fetch(path, options);
    let payload = null;
    if (response.status !== 204) {
      const contentType = String(response.headers.get('content-type') || '').toLowerCase();
      if (contentType.includes('application/json')) {
        payload = await response.json();
      } else {
        const text = await response.text();
        payload = text ? {error: text} : {};
      }
    }

    if (!response.ok) {
      const message = payload && typeof payload === 'object'
        ? String(payload.error || payload.message || `${response.status} ${response.statusText}`)
        : `${response.status} ${response.statusText}`;
      throw new Error(message);
    }
    return payload || {};
  }
})();
