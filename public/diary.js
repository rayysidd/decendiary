document.addEventListener('DOMContentLoaded', () => {
    const token = sessionStorage.getItem('token');
    if (!token) {
        window.location.href = '/index.html';
        return;
    }

    const entryForm = document.getElementById('entry-form');
    const entryText = document.getElementById('entry-text');
    const entriesList = document.getElementById('entries-list');
    const logoutBtn = document.getElementById('logout-btn');
    const formButton = entryForm.querySelector('button');

    const showLoading = (isLoading) => {
        formButton.disabled = isLoading;
        formButton.textContent = isLoading ? 'Saving...' : 'Save Entry';
    };

    const fetchEntries = async () => {
        const res = await fetch('/api/entries', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (res.status === 403 || res.status === 401) {
            sessionStorage.removeItem('token');
            window.location.href = '/index.html';
            return;
        }

        const entries = await res.json();
        entriesList.innerHTML = ''; // Clear the list before rendering
        entries.forEach(entry => {
            const entryEl = document.createElement('li');
            entryEl.className = 'entry';
            entryEl.innerHTML = `
                <p>${entry.encrypted_text}</p>
                <div class="entry-meta">Created at: ${new Date(entry.created_at).toLocaleString()}</div>
                <div class="entry-actions">
                    <button class="edit-btn" data-id="${entry.id}">Edit</button>
                    <button class="delete-btn" data-id="${entry.id}">Delete</button>
                </div>
            `;
            entriesList.appendChild(entryEl);
        });
    };

    entryForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading(true);
        const text = entryText.value;
        await fetch('/api/entries', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ entryText: text })
        });
        entryText.value = '';
        showLoading(false);
        await fetchEntries();
    });

    entriesList.addEventListener('click', async (e) => {
        const entryId = e.target.dataset.id;
        
        if (e.target.classList.contains('delete-btn')) {
            // UX Improvement: Confirm before deleting
            if (confirm('Are you sure you want to delete this entry?')) {
                await fetch(`/api/entries/${entryId}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                await fetchEntries();
            }
        }

        if (e.target.classList.contains('edit-btn')) {
            const currentText = e.target.closest('.entry').querySelector('p').textContent;
            const newText = prompt('Edit your entry:', currentText);
            if (newText !== null && newText !== currentText) {
                await fetch(`/api/entries/${entryId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ entryText: newText })
                });
                await fetchEntries();
            }
        }
    });
    
    logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('token');
        window.location.href = '/index.html';
    });

    fetchEntries();
});