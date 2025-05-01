# processing the data

import json
import random

def lstm_data():
  youtube_data = []
  zoom_data = []
  twitch_data = []

  youtube_data_files = ['data/300pkts/youtube_01.json', 'data/300pkts/youtube_02.json', 'data/300pkts/youtube_03.json']
  zoom_data_files = ['data/300pkts/zoom_01.json']
  twitch_data_files = ['data/300pkts/twitch_01.json', 'data/300pkts/twitch_02.json']

  # load data from json files
  for file in youtube_data_files:
    with open(file, 'r') as f:
      f_data = json.load(f)
      for d in f_data:
        if len(d) != 300:
          continue
        youtube_data.append(d)

  for file in zoom_data_files:
    with open(file, 'r') as f:
      f_data = json.load(f)
      for d in f_data:
        if len(d) != 300:
          continue
        zoom_data.append(d)

  for file in twitch_data_files:
    with open(file, 'r') as f:
      f_data = json.load(f)
      for d in f_data:
        if len(d) != 300:
          continue
        twitch_data.append(d)

  # randomly shuffle the data and put in the dataset
  data = []
  youtube_data_num = len(youtube_data)
  zoom_data_num = len(zoom_data)
  twitch_data_num = len(twitch_data)
  youtube_data_ptr = 0
  zoom_data_ptr = 0
  twitch_data_ptr = 0

  while youtube_data_ptr < youtube_data_num or zoom_data_ptr < zoom_data_num or twitch_data_ptr < twitch_data_num:
    # generate a random number
    rand_num = random.randint(0, 2)
    if rand_num == 0 and youtube_data_ptr < youtube_data_num:
      data.append({
        "features": youtube_data[youtube_data_ptr],
        "label": 0
      })
      youtube_data_ptr += 1
    elif rand_num == 1 and zoom_data_ptr < zoom_data_num:
      data.append({
        "features": zoom_data[zoom_data_ptr],
        "label": 1
      })
      zoom_data_ptr += 1
    elif rand_num == 2 and twitch_data_ptr < twitch_data_num:
      data.append({
        "features": twitch_data[twitch_data_ptr],
        "label": 2
      })
      twitch_data_ptr += 1

  output_file = 'data/300pkts/lstm_data.json'
  with open(output_file, 'w', encoding="utf-8") as f:
    json.dump(data, f)
  
  
def random_forest_data():
  youtube_data = []
  zoom_data = []
  twitch_data = []

  youtube_data_files = ['data/1min/youtube_01.json', 'data/1min/youtube_02.json', 'data/1min/youtube_03.json']
  zoom_data_files = ['data/1min/zoom_01.json', 'data/1min/zoom_02.json']
  twitch_data_files = ['data/1min/twitch_01.json', 'data/1min/twitch_02.json']

  # load data from json files
  for file in youtube_data_files:
    with open(file, 'r') as f:
      f_data = json.load(f)
      for d in f_data:
        youtube_data.append(d)

  for file in zoom_data_files:
    with open(file, 'r') as f:
      f_data = json.load(f)
      for d in f_data:
        zoom_data.append(d)

  for file in twitch_data_files:
    with open(file, 'r') as f:
      f_data = json.load(f)
      for d in f_data:
        twitch_data.append(d)

  print(len(youtube_data), len(zoom_data), len(twitch_data))


  

if __name__ == "__main__":
    # lstm_data()
    random_forest_data()