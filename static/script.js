document.addEventListener('DOMContentLoaded', function () {
    function showToast(message, type) {

    const toast = document.getElementById("toast");

    toast.innerText = message;
    toast.classList.remove("success", "error", "hidden");

    if (type === "success") {
        toast.classList.add("success");
    } else {
        toast.classList.add("error");
    }

    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
        toast.classList.add("hidden");
    }, 3000);
}

    /* ===================== ELEMENTS ===================== */

    const manufacturingDateCheckbox = document.getElementById('manufacturingDate');
    const dateInput = document.getElementById('dateInput');
    const actionButton = document.getElementById('actionButton');

    const resultCard = document.getElementById('resultCard');
    const resultTitle = document.getElementById('resultTitle');
    const resultStatus = document.getElementById('resultStatus');
    const resultExpiry = document.getElementById('resultExpiry');
    const savePantryBtn = document.getElementById('savePantryBtn');
    /* ===================== INITIAL STATE ===================== */

    dateInput.style.display = 'none';
    savePantryBtn.style.display = 'none';

    /* ===================== DATE TOGGLE ===================== */

    manufacturingDateCheckbox.addEventListener('change', function () {
        dateInput.style.display = this.checked ? 'block' : 'none';
        actionButton.textContent = this.checked ? 'Calculate Expiry Date' : 'Show Shelf Life';
    });


    /* ===================== STORAGE ===================== */

    document.querySelectorAll('.storage-option').forEach(option => {
        option.addEventListener('click', function () {
            document.querySelectorAll('.storage-option')
                .forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
        });
    });

    /* ===================== INFO SECTIONS ===================== */

    function setupToggle(headerId, contentId, arrowId) {
        const header = document.getElementById(headerId);
        const content = document.getElementById(contentId);
        const arrow = document.getElementById(arrowId);

        header.addEventListener('click', function () {
            content.classList.toggle('active');
            arrow.classList.toggle('arrow-down');
        });
    }

    setupToggle('warningHeader', 'warningContent', 'warningArrow');
    setupToggle('tipsHeader', 'tipsContent', 'tipsArrow');
    setupToggle('expiryTermsHeader', 'expiryContent', 'expiryArrow');
    setupToggle('storageImpactHeader', 'storageContent', 'storageArrow');

    /* ===================== RESULT HELPERS ===================== */

    function resetResults() {
        resultCard.classList.add("hidden");
        resultCard.classList.remove("safe", "expired");
        resultTitle.innerText = "";
        resultStatus.innerText = "";
        resultExpiry.innerText = "";
        savePantryBtn.style.display = "none";
    }

    function showError(message) {
        resultCard.classList.remove("hidden", "safe");
        resultCard.classList.add("expired");

        resultTitle.innerText = "⚠ ERROR";
        resultStatus.innerText = message;
        resultExpiry.innerText = "";
        savePantryBtn.style.display = "none";
    }

    function showShelfLife(days) {
        resultCard.classList.remove("hidden", "expired");
        resultCard.classList.add("safe");

        resultTitle.innerText = "📦 SHELF LIFE";
        resultStatus.innerText = `${days} day(s)`;
        resultExpiry.innerText = "";
        savePantryBtn.style.display = "none";
        
    }

    function showExpiryResult(expiryDateStr) {
        const expiryDate = new Date(expiryDateStr);
        const today = new Date();
        const diffDays = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));

        resultCard.classList.remove("hidden", "safe", "expired");

        if (diffDays < 0) {
            resultCard.classList.add("expired");
            resultTitle.innerText = "❌ EXPIRED";
            resultStatus.innerText = `Expired ${Math.abs(diffDays)} day(s) ago`;
        } else {
            resultCard.classList.add("safe");
            resultTitle.innerText = "✅ SAFE TO USE";
            resultStatus.innerText = `${diffDays} day(s) remaining`;
        }

        resultExpiry.innerText = `Expiry Date: ${expiryDateStr}`;
        savePantryBtn.style.display = "inline-block";
    }

    /* ===================== ACTION BUTTON ===================== */

    actionButton.addEventListener('click', async () => {

        resetResults();

        const manufacturingDate = manufacturingDateCheckbox.checked;
        const date = dateInput.value;
        const storage = document.querySelector('.storage-option.active')?.dataset?.storage;
        const opened = document.getElementById('openedToggle').checked;

        if (!storage) {
            showError("Please select a storage condition.");
            return;
        }

        const product = document.querySelector('.product-search').value.trim();

        if (!product) {
            showError("Please enter a product name.");
            return;
        }

        try {
            const res = await fetch('/get-product', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    product,
                    storage,
                    opened,
                    manufacturing_date: manufacturingDate ? date : null
                })
            });

            const data = await res.json();

            if (data.status === "success") {
                if (data.expiry_date) {
                    showExpiryResult(data.expiry_date);
                } else {
                    showShelfLife(data.shelf_life);
                }
            } else {
                showError(data.message);
            }

        } catch {
            showError("Something went wrong!");
        }

    });

/* ===================== SAVE TO PANTRY ===================== */

savePantryBtn.addEventListener("click", async function () {

    this.disabled = true;

    const product = document.querySelector('.product-search')?.value?.trim();
    const expiryText = resultExpiry.innerText;

    if (!expiryText.includes("Expiry Date:")) {
        showToast("No expiry date available.", "error");
        this.disabled = false;
        return;
    }

    const expiry_date = expiryText.replace("Expiry Date: ", "");

    try {

        const res = await fetch("/save-to-pantry", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                product: product,
                expiry_date: expiry_date
            })
        });

        const data = await res.json();

        if (data.status === "success") {
            showToast(data.message || "Saved to Pantry!", "success");
        } else {
            showToast(data.message || "Error", "error");
        }

    } catch {
        showToast("Server error.", "error");
    }

    this.disabled = false;
});


async function loadPantryStats() {

    const res = await fetch('/pantry-stats');
    const data = await res.json();

    const badge = document.getElementById('expiryBadge');
    const expiredSpan = document.getElementById('badgeExpired');
    const soonSpan = document.getElementById('badgeSoon');

    if (data.expired === 0 && data.soon === 0) {
        badge.classList.add('hidden');
        return;
    }

    badge.classList.remove('hidden');

    expiredSpan.innerHTML = `🔴 Expired: ${data.expired}`;
    soonSpan.innerHTML = `🟡 Expiring Soon: ${data.soon}`;
}

loadPantryStats();



document.querySelectorAll(".deleteBtn").forEach(btn => {

    btn.addEventListener("click", async function() {

        const card = this.closest(".item-card");
        const itemId = this.dataset.id;

        // 🔥 Remove instantly (smooth UX)
        card.style.opacity = "0.5";
        card.remove();

        try {
            await fetch('/delete-from-pantry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ item_id: itemId })
            });

            showToast("Item deleted", "success");

        } catch (err) {
            showToast("Error deleting item", "error");
        }
    });

});
});
