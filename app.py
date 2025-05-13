# 1. Import libraries
from flask import Flask, request, render_template
import numpy as np
import pickle
from feature import FeatureExtraction
import warnings

warnings.filterwarnings('ignore')

# 2. Create the Flask app
app = Flask(__name__)

# 3. Load model
with open("pickle/model.pkl", "rb") as f:
    gbc = pickle.load(f)

# 4. Define the route
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList() + [0]).reshape(1, 31)

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        safe_score = round(y_pro_non_phishing * 100, 2)

        # Updated threshold to 80%
        if y_pred == 1 and safe_score >= 80:
            pred = "Safe website ✅"
        else:
            pred = "Phishing website 🚨"

        return render_template(
            'index.html',
            xx=safe_score, 
            pred=pred,
            url=url
        )

    return render_template("index.html", xx=-1, pred='', url='')

# 5. Run the app
if __name__ == "__main__":
    app.run(debug=True)
