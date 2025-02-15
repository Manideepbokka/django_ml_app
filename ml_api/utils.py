import torch
import pandas as pd
import os
import numpy as np
from .models import ModifiedNet  # Ensure ModifiedNet is defined correctly in models.py

def load_model(file_name, input_features):
    base_path = os.path.join(os.path.dirname(__file__), "ml_models")
    model_path = os.path.join(base_path, file_name)

    # Register ModifiedNet to resolve deserialization
    import sys
    sys.modules["__main__"].ModifiedNet = ModifiedNet

    # Load the checkpoint
    checkpoint = torch.load(model_path, map_location=torch.device("cpu"))

    # Initialize the model architecture
    model = ModifiedNet(input_features)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()  # Set model to evaluation mode

    return {
        "model": model,
        "preprocessor": checkpoint["preprocessor"],
        "target_scaler": checkpoint["target_scaler"],
    }

# Load all models with specific input features
models = {
    "gaCo2": load_model("best_model_GACO2.pth", input_features=19),
    "gaTotalEnergyRate": load_model("best_model_GAEnergyRate.pth", input_features=20),
    "gaNOx": load_model("best_model_GANOx.pth", input_features=19),
    "gaPM2.5BrakeWear": load_model("best_model_GAPM2.5Brakewear.pth", input_features=20),
    "gaPM2.5TireWear": load_model("best_model_GAPM2.5Tirewear.pth", input_features=19),
}

# Function to predict values for all models
def predict_all(inputs):
    predictions = {}

    for key, model_info in models.items():
        model = model_info["model"]
        preprocessor = model_info["preprocessor"]
        target_scaler = model_info["target_scaler"]

        # Preprocess the input
        df = pd.DataFrame([inputs])  # Convert input to DataFrame
        processed_input = preprocessor.transform(df)  # Preprocess the input data

        # Convert to tensor (ensure compatibility for sparse arrays)
        if hasattr(processed_input, "toarray"):  # Handle sparse matrices
            input_tensor = torch.tensor(processed_input.toarray(), dtype=torch.float32)
        else:
            input_tensor = torch.tensor(processed_input, dtype=torch.float32)

        # Predict the output
        with torch.no_grad():
            raw_prediction = model(input_tensor)  # Predict using the model
            prediction = target_scaler.inverse_transform(raw_prediction.numpy())  # Scale back to original

        # Store the prediction
        predictions[key] = prediction[0][0]  # Extract the predicted value

    return predictions
