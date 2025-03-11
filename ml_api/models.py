from django.db import models
import torch
import torch.nn as nn
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    otp = models.IntegerField(null=True, blank=True)  # To store OTP
    otp_verified = models.BooleanField(default=False)

    

class PredictionLog(models.Model):
    user_id = models.IntegerField()
    age = models.IntegerField()
    speed = models.FloatField()
    vehicle_type = models.CharField(max_length=50)
    fuel_type = models.CharField(max_length=50)
    city = models.CharField(max_length=100, null=True, blank=True)
    ga_co2 = models.FloatField()
    ga_total_energy_rate = models.FloatField()
    ga_nox = models.FloatField()
    ga_pm25_brake_wear = models.FloatField()
    ga_pm25_tire_wear = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for creation

    def __str__(self):
        return f"PredictionLog(user_id={self.user_id}, created_at={self.created_at})"


class ModifiedNet(torch.nn.Module):
    def __init__(self, input_features):
        super(ModifiedNet, self).__init__()
        self.fc1 = nn.Linear(input_features, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc3 = nn.Linear(256, 128)
        self.fc4 = nn.Linear(128, 64)
        self.fc5 = nn.Linear(64, 1)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        x = torch.relu(self.fc3(x))
        x = torch.relu(self.fc4(x))
        x = self.fc5(x)
        return x