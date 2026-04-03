# Vehicle Digital Twin - React UI

A modern, professional React-based UI that replaces the Streamlit interface with improved performance and no flickering issues.

## Features

- **Clean Professional UI**: Modern design with Lucide React icons
- **Real-time Updates**: 300ms refresh rate without flickering
- **Single Page Application**: All components in one seamless interface
- **Responsive Design**: Works on desktop and mobile devices
- **Performance Optimized**: No data reload issues like Streamlit

## Quick Start

### Option 1: Automated Setup
```bash
./start_react_app.sh
```

### Option 2: Manual Setup

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install React Dependencies**
   ```bash
   cd react-app
   npm install
   ```

3. **Start Flask API** (Terminal 1)
   ```bash
   python react_api.py
   ```

4. **Start React App** (Terminal 2)
   ```bash
   cd react-app
   npm start
   ```

5. **Start CAN Generator** (Terminal 3)
   ```bash
   python can_generator.py
   ```

## Access Points

- **React UI**: http://localhost:3000
- **Flask API**: http://localhost:5000
- **Original Streamlit**: `streamlit run digital_twin_app.py` (if needed)

## UI Components

### 🏠 Header Section
- Vehicle status overview
- Real-time position and speed display
- Clean typography with car icon

### 🔒 Security Status Panel
- Trust score with color-coded indicators
- ML detection mode toggle
- Data source status (Kafka/CAN)

### 🎯 ML Toggle Control
- Interactive switch for ML detection
- Real-time mode switching
- Demo explanation panel

### 🎮 ECU Commands
- Professional button layout
- Icon-based controls (arrows, reset)
- Instant CAN message sending

### 📊 Vehicle Visualization
- Interactive Plotly.js chart
- Real-time vehicle position
- Heading indicator

### 📈 Metrics Dashboard
- 6-panel metric display
- Icon-based indicators
- Real-time value updates

### 📜 Security Log
- Tabular message display
- Color-coded status indicators
- Scrollable history

## Architecture

```
React Frontend (Port 3000)
    ↓ HTTP API calls
Flask Backend (Port 5000)
    ↓ Direct integration
CAN Listener + Security Pipeline
    ↓ CAN messages
Vehicle State + Trust Engine
```

## Advantages over Streamlit

1. **No Flickering**: React's virtual DOM prevents UI flicker
2. **Better Performance**: Optimized rendering and state management
3. **Professional UI**: Modern design with proper icons
4. **Responsive**: Works on all screen sizes
5. **Extensible**: Easy to add new components
6. **Real-time**: WebSocket support ready for future enhancements

## Technology Stack

- **Frontend**: React 18, Tailwind CSS, Lucide React icons
- **Charts**: Plotly.js with React integration
- **Backend**: Flask with CORS support
- **State Management**: React hooks
- **Styling**: Tailwind CSS utility classes

## Development

To modify the UI:
1. Edit `react-app/src/App.js` for components
2. Edit `react-app/src/App.css` for custom styles
3. Edit `react_api.py` for backend endpoints

The React app will hot-reload automatically during development.