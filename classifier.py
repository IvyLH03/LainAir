import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import json

# load data from json file
with open('data/300pkts/lstm_data.json', 'r') as f:
    data = json.load(f)

for i in range(5):
    print(data[i])
    print("")

# Map labels to integers (YouTube = 0, Zoom = 1, Twitch = 2)
label_map = {'YouTube': 0, 'Zoom': 1, 'Twitch': 2}

# Custom Dataset class
class TrafficDataset(Dataset):
    def __init__(self, data, label_map):
        self.data = data  # Dataset
        self.label_map = label_map  # Label mapping (YouTube -> 0, etc.)
        
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        features = torch.tensor(self.data[idx]['features'], dtype=torch.float32)
        label = self.label_map[self.data[idx]['label']]  # Convert label to int
        return features, label

# Create Dataset and DataLoader
dataset = TrafficDataset(data, label_map)
dataloader = DataLoader(dataset, batch_size=2, shuffle=True)  # Use a small batch size for quick testing

# Define LSTM Model
class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(LSTMModel, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)
        
    def forward(self, x):
        lstm_out, (hn, cn) = self.lstm(x)
        out = self.fc(hn[-1])  # Use the last hidden state
        return out

# Define model (3 features per packet)
model = LSTMModel(input_size=3, hidden_size=64, output_size=3)  # Output: 3 classes (YouTube, Zoom, Twitch)

# Loss and Optimizer
criterion = nn.CrossEntropyLoss()  # For multi-class classification
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Training loop
epochs = 5  # Training for a few epochs due to time constraint
for epoch in range(epochs):
    model.train()
    running_loss = 0.0
    for inputs, labels in dataloader:
        # Forward pass
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        
        # Backward pass and optimization
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        running_loss += loss.item()
    
    print(f"Epoch [{epoch+1}/{epochs}], Loss: {running_loss/len(dataloader)}")

# Evaluation loop
model.eval()
with torch.no_grad():
    total, correct = 0, 0
    for inputs, labels in dataloader:
        outputs = model(inputs)
        _, predicted = torch.max(outputs, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()

    print(f"Accuracy: {100 * correct / total}%")
