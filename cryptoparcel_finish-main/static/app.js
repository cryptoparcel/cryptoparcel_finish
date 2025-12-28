document.addEventListener("DOMContentLoaded", function () {
  const serviceSelect = document.getElementById("service");
  const weightInput = document.getElementById("weight_oz");
  const estimateEl = document.getElementById("price-estimate");
  const priceCard = document.getElementById("price-card");

  function calculatePrice(service, weightOz) {
    if (!service || isNaN(weightOz) || weightOz <= 0) {
      return null;
    }
    let basePrice = 3.0;
    const perOz = 0.10;
    const fastKeywords = ["express", "overnight", "priority", "next day", "2day", "2-day"];
    const svcLower = service.toLowerCase();
    if (fastKeywords.some((k) => svcLower.includes(k))) {
      basePrice += 2.0;
    }
    const total = basePrice + weightOz * perOz;
    return Math.round(total * 100) / 100;
  }

  function updateEstimate() {
    if (!serviceSelect || !weightInput || !estimateEl || !priceCard) return;
    const service = serviceSelect.value || "";
    const weight = parseFloat(weightInput.value);
    const price = calculatePrice(service, weight);
    if (price == null) {
      estimateEl.textContent = "—";
      priceCard.classList.remove("price-card-active");
    } else {
      estimateEl.textContent = `$${price.toFixed(2)} USD`;
      priceCard.classList.add("price-card-active");
    }
  }

  if (serviceSelect && weightInput && estimateEl && priceCard) {
    serviceSelect.addEventListener("change", updateEstimate);
    weightInput.addEventListener("input", updateEstimate);
    updateEstimate();
  }
});
