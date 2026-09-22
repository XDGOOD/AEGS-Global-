"""
AEGS Titan - QR Code Generator for 1-Click Mobile App Onboarding
"""

import io
import urllib.parse
import urllib.request
import logging

logger = logging.getLogger('qr_generator')

def get_qr_image_bytes(text: str) -> bytes:
    """
    Generates QR code PNG bytes for the given subscription text.
    Uses local 'qrcode' library if available, otherwise falls back to reliable QR API.
    """
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()
    except ImportError:
        # High-reliability fallback to QR generation API
        encoded_data = urllib.parse.quote(text)
        url = f"https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={encoded_data}"
        req = urllib.request.Request(url, headers={'User-Agent': 'AEGS-Titan-Bot/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read()
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        raise
