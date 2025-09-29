# Phishing Website Detection using Big Data Analytics

This project uses a Random Forest machine learning model to detect phishing websites. It includes a web application built with Streamlit that allows users to enter a URL and get a prediction on whether it's a phishing or legitimate website.

-----

## 🚀 Features

  * **Machine Learning Model**: A Random Forest Classifier is trained on a dataset of phishing and legitimate URLs to make predictions.
  * **Web Application**: A user-friendly web interface built with Streamlit to interact with the model.
  * **Feature Extraction**: Extracts various features from the URL to determine its legitimacy, including checks for brand mismatch, protocol safety, and suspicious subdomains.
  * **Detection History**: The application keeps a history of all the detected URLs, which can be viewed on the History Dashboard.

-----

## 🏁 Getting Started

### Prerequisites

You'll need to have Python and pip installed. The required Python libraries are listed in the `requrirements.txt` file and can be installed using the command below.

  * python-whois
  * streamlit
  * pandas
  * scikit-learn
  * joblib

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/siddh113/Phishing-Big-Data-Analytics.git
    ```
2.  **Navigate to the project directory:**
    ```sh
    cd Phishing-Big-Data-Analytics
    ```
3.  **Install the required libraries:**
    ```sh
    pip install -r requrirements.txt
    ```

-----

## 🎈 Usage

### Running the Application

To run the Streamlit application, execute the following command in your terminal:

```sh
streamlit run app3.py
```

### How to Use the App

The application has two main views that can be selected from the sidebar:

  * **Detector**: Paste a URL in the text box and click the "Detect" button. The app will analyze the URL and tell you if it's likely a phishing or legitimate website.
  * **History Dashboard**: This view displays a history of all the URLs that have been checked, along with the prediction and confidence score.

-----

## 🤖 Model

### Dataset

The model was trained on the `PhishingDataset.csv` dataset, which contains a collection of features from both phishing and legitimate websites.

### Model Training

The `PhishingDetection_Big_Data_Analytics.ipynb` notebook contains the complete process of data exploration, preprocessing, and model training. A Random Forest Classifier was chosen as the model, and its hyperparameters were tuned using GridSearchCV for optimal performance. The final trained model is saved in the `phishing_rf_model2.pkl` file.

-----

## 🤝 Contributing

Contributions are welcome\! Please feel free to submit a pull request or open an issue if you have any suggestions or find any bugs.
