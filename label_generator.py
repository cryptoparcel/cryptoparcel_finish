from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO


def generate_shipping_label_pdf(order):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)

    text = c.beginText(72, 720)
    text.setFont("Helvetica", 12)
    text.textLine("CryptoParcel Shipping Label")
    text.textLine(f"Order ID: {order.id}")
    text.textLine("")
    text.textLine("From:")
    for line in (order.from_address or "").splitlines():
        text.textLine(line)
    text.textLine("")
    text.textLine("To:")
    for line in (order.to_address or "").splitlines():
        text.textLine(line)
    text.textLine("")
    text.textLine(f"Carrier: {order.carrier}")
    text.textLine(f"Service: {order.service}")
    text.textLine(f"Weight: {order.weight_oz} oz")
    text.textLine("")
    text.textLine(f"Amount Paid: ${order.amount_usd:.2f} USD (via crypto)")

    c.drawText(text)
    c.showPage()
    c.save()

    pdf = buffer.getvalue()
    buffer.close()
    return pdf
