from lstm_classifier import LSTMModel, TrafficDataset, load_data
import torch
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

# load model
model = LSTMModel(input_size=3, hidden_size=64, output_size=3)  # Output: 3 classes (YouTube, Zoom, Twitch)
model.load_state_dict(torch.load('lstm_traffic_classifier.pth'))

model.eval()

all_preds = []
all_labels = []

dataloader = load_data('data/300pkts/lstm_data.json')

with torch.no_grad():
    for inputs, labels in dataloader:
        outputs = model(inputs)
        _, preds = torch.max(outputs, 1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

# Plot confusion matrix
cm = confusion_matrix(all_labels, all_preds)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["YouTube", "Zoom", "Twitch"])
disp.plot(cmap=plt.cm.Blues)
plt.title("Confusion Matrix - LSTM Model")
plt.savefig("confusion_matrix_lstm.png")  # <-- Save it!
plt.show()
