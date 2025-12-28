from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas


def generate_shipping_label_pdf(order):
    """Generate a simple but more polished PDF label for a shipping order."""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Outer border
    margin = 0.5 * inch
    c.setLineWidth(1)
    c.rect(margin, margin, width - 2 * margin, height - 2 * margin)

    # Header / branding
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin + 10, height - margin - 20, "CryptoParcel Shipping Label")

    c.setFont("Helvetica", 10)
    c.drawString(margin + 10, height - margin - 40, f"Order ID: {order.id}")
    c.drawString(margin + 10, height - margin - 55, f"Carrier: {order.carrier}  |  Service: {order.service}")
    if getattr(order, "amount_usd", None) is not None:
        try:
            amt = float(order.amount_usd or 0.0)
            c.drawString(margin + 10, height - margin - 70, f"Amount: ${amt:.2f} USD")
        except Exception:
            pass

    # From / To blocks
    y_start = height - margin - 110
    block_width = (width - 2 * margin - 20) / 2

    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin + 10, y_start, "From")
    c.drawString(margin + 10 + block_width + 10, y_start, "To")

    c.setFont("Helvetica", 10)
    y_text = y_start - 15

    from_lines = []
    if getattr(order, "from_address", None):
        from_lines = [line for line in str(order.from_address).split("\n") if line.strip()]
    to_lines = []
    if getattr(order, "to_address", None):
        to_lines = [line for line in str(order.to_address).split("\n") if line.strip()]

    for i, line in enumerate(from_lines[:6]):
        c.drawString(margin + 10, y_text - i * 12, line)

    for i, line in enumerate(to_lines[:6]):
        c.drawString(margin + 10 + block_width + 10, y_text - i * 12, line)

    # Weight line
    y_weight = y_text - 6 * 12 - 10
    try:
        c.drawString(margin + 10, y_weight, f"Weight: {float(order.weight_oz):.2f} oz")
    except Exception:
        c.drawString(margin + 10, y_weight, "Weight: -")

    # Reference / notes
    if getattr(order, "reference", None):
        c.drawString(margin + 10, y_weight - 14, f"Reference: {order.reference}")

    # Simple faux barcode at bottom
    barcode_y = margin + 40
    c.setFont("Helvetica", 18)
    c.drawString(margin + 10, barcode_y, "|" * 50)
    c.setFont("Helvetica", 8)
    c.drawString(margin + 10, barcode_y - 10, "Not a real barcode — for layout preview only.")

    # Footer note
    c.setFont("Helvetica", 7)
    c.drawString(
        margin + 10,
        margin + 15,
        "CryptoParcel demo label — not affiliated with USPS, UPS, or FedEx. For testing and internal use only.",
    )

    c.showPage()
    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    return pdf
