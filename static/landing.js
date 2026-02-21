document.addEventListener("DOMContentLoaded", function () {

    const cards = document.querySelectorAll(".feature-card");

    cards.forEach((card, index) => {
        card.style.opacity = 0;
        card.style.transform = "translateY(20px)";

        setTimeout(() => {
            card.style.transition = "all 0.6s ease";
            card.style.opacity = 1;
            card.style.transform = "translateY(0)";
        }, index * 150);
    });
const form = document.getElementById("suggestionForm");
const message = document.getElementById("suggestionMessage");

if (form) {
    form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const email = document.getElementById("suggestionEmail").value;
    const messageText = document.getElementById("suggestionText").value;

    if (!messageText.trim()) {
        message.style.color = "red";
        message.innerText = "Message cannot be empty.";
        return;
    }

    try {
        const response = await fetch("/submit-suggestion", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: "Anonymous",
                email: email,
                message: messageText
            })
        });

        if (!response.ok) {
            throw new Error("Server error");
        }

        const result = await response.json();

        if (result.status === "success") {
            message.style.color = "#3ba55d";
            message.innerText = "Thank you! Your suggestion has been received.";
            form.reset();
        } else {
            message.style.color = "red";
            message.innerText = result.message || "Failed to submit.";
        }

    } catch (error) {
        message.style.color = "red";
        message.innerText = "Something went wrong.";
    }

    setTimeout(() => {
        message.innerText = "";
    }, 4000);
});}

});
