from flask import Flask, render_template, request, url_for
import pandas as pd
from URLFeatureExtraction import featureExtraction
import numpy as np
import joblib,os
import pickle


app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/detect")
def detect():
    return render_template('detect.html')

@app.route("/about")
def about():
    return render_template('aboutus.html')


@app.route("/result", methods=['POST'])
def result():

    # Load model pickle
    phish_model = open('XGBoostClassifier.pickle.DAT','rb')
    phish_model_ls = joblib.load(phish_model)

    if request.method == 'POST':
        url = request.form['url']
        
        features=featureExtraction(url)
        features = np.array(features).reshape(1,-1)
        y_Predict = phish_model_ls.predict(features)

        if y_Predict == 0:
            temp="NOT a phishing URL"
        else:
            temp="Phishing URL"

    return render_template('result.html', prediction=y_Predict ,fea=features,t=temp)


if __name__ == "__main__":
    app.run(debug=True)