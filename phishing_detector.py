import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split

TRAINING_DATA = [
    ("Dear customer, your bank account has been locked. Click here to verify your identity immediately http://secure-bank-login-update.com", "Phishing"),
    ("Urgent: Your Netflix subscription has expired. Update your payment details now at http://netflix-billing-support.net", "Phishing"),
    ("Verify your account details within 24 hours to avoid suspension. Click http://paypal-security-alert.org", "Phishing"),
    ("Congratulations! You won a $1000 Amazon gift card. Claim your prize here: http://free-rewards-center.com", "Phishing"),
    ("ALERT: Unusual login activity detected on your account. Reset password via http://google-security-recovery.info", "Phishing"),
    ("Hi team, please find attached the meeting minutes from our sync earlier today. Thanks!", "Safe"),
    ("Hey, are we still on for lunch tomorrow afternoon? Let me know what time works.", "Safe"),
    ("Your monthly electricity bill is now available online. Log into your standard portal to view.", "Safe"),
    ("Hi John, thanks for sending over the project update. I will review it by Friday morning.", "Safe"),
    ("The company all-hands meeting has been rescheduled to Thursday at 10:00 AM.", "Safe")
]

def prepare_and_train():
    emails = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]
    
    vectorizer = TfidfVectorizer(stop_words='english', lowercase=True)
    X = vectorizer.fit_transform(emails)
    y = np.array(labels)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    model = MultinomialNB()
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred, labels=["Safe", "Phishing"])
    
    return model, vectorizer, accuracy, cm

def classify_email(email_text, model, vectorizer):
    vectorized_text = vectorizer.transform([email_text])
    prediction = model.predict(vectorized_text)[0]
    probabilities = model.predict_proba(vectorized_text)[0]
    confidence = max(probabilities) * 100
    return prediction, round(confidence, 2)

if __name__ == "__main__":
    print("--- Phishing Email Detection Model ---")
    print("Training the model on initial security dataset...")
    
    model, vectorizer, accuracy, cm = prepare_and_train()
    
    print("\n--- Model Performance Evaluation ---")
    print(f"Model Accuracy: {accuracy * 100:.1f}%")
    print("Confusion Matrix:")
    print(f" [ True Safe: {cm[0][0]}   False Phishing: {cm[0][1]} ]")
    print(f" [ False Safe: {cm[1][0]}   True Phishing: {cm[1][1]} ]")
    print("-------------------------------------")
    
    print("\nTest the model with a custom email block.")
    user_email = input("Enter email text to analyze: ").strip()
    
    if user_email:
        result, confidence = classify_email(user_email, model, vectorizer)
        print("\n--- Analysis Result ---")
        print(f"Classification : {result}")
        print(f"Confidence     : {confidence}%")
        print("-----------------------")
