import joblib,os
from URLFeatureExtraction import featureExtraction
import numpy as np

url=input()
features=featureExtraction(url)
print(features)

#pkl
phish_model = open('XGBoostClassifier.pickle.DAT','rb')
phish_model_ls = joblib.load(phish_model)
features = np.array(features).reshape(1,-1)
y_Predict = phish_model_ls.predict(features)

print(y_Predict)
if y_Predict == 0:
	result = "This is not Phishing Site"
else:
	result = "This is  a Phishing Site"

print(result)
