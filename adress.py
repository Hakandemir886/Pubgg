from flask import Flask, jsonify, request
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime

app = Flask(__name__)

# Rate Limiting (Her IP için 5 saniyede bir istek izni)
limiter = Limiter(get_remote_address, app=app)

# Veri dosyasının yolu
FILE_PATH = "/storage/emulated/0/Download/adres.txt"

# API güvenlik başlıkları
@app.after_request
def apply_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Rate limiting sınırını aştığında mesaj göster
@app.errorhandler(429)  # 429: Too Many Requests
def rate_limit_error(e):
    return jsonify({
        "error": "Çok fazla istek gönderdiniz. Lütfen 5 saniye bekleyin."
    }), 429

@app.route('/get-data/<tc_no>', methods=['GET'])
@limiter.limit("1 per 5 seconds")  # Rate Limiting: Her IP için 5 saniyede 1 istek
def get_data(tc_no):
    try:
        tc_no = str(tc_no).strip()  # Boşlukları temizle ve string olarak al

        # Veri dosyasını oku ve TC'yi bul
        with open(FILE_PATH, 'r', encoding='utf-8') as file:
            for line in file:
                # Parantezleri ve tek tırnakları temizle
                cleaned_line = re.sub(r"[()']", "", line.strip())

                # Virgülle ayır ve her elemanı temizle
                record = [x.strip() for x in cleaned_line.split(",")]

                if len(record) < 10:  # Eksik satırları atla
                    continue

                if record[1] == tc_no:  # TC kimlik numarası eşleşme kontrolü
                    result = {
                        "ID": record[0],
                        "TC": record[1],
                        "Ad": record[2],
                        "Soyad": record[3],
                        "Doğum Yeri": record[4],
                        "Baba Adı": record[5],
                        "Doğum Tarihi": record[6],
                        "Cinsiyet": record[7],
                        "Yaş": record[8],
                        "Açık Adres": record[9] if len(record) > 9 else "Adres Bilgisi Yok"
                    }

                    return jsonify({"result": result, "auth": "@sanalmafyax"})

        return jsonify({"message": "Bu TC kimlik numarasına sahip veri bulunamadı.", "auth": "@sanalmafyax"})

    except Exception as e:
        return jsonify({"error": str(e), "auth": "@sanalmafyax"}), 500

if __name__ == '__main__':
    app.run(debug=False)