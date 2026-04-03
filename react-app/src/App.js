import React, { useState, useEffect } from 'react';
import { 
  Car, Shield, Activity, AlertTriangle, CheckCircle, 
  ArrowLeft, ArrowRight, ArrowUp, ArrowDown, RotateCcw,
  Wifi, WifiOff, Target, Lock, Unlock, LogOut, User
} from 'lucide-react';
import Plot from 'react-plotly.js';
import { AuthProvider, useAuth, withAuth } from './Auth';
import './App.css';

const Dashboard = () => {
  const { user, logout, isAdmin, token } = useAuth();
  const [vehicleState, setVehicleState] = useState({
    speed: 0,
    x_position: 0,
    y_position: 0,
    heading: 0,
    steering_angle: 0,
    brake_pressure: 0
  });

  const [securityStatus, setSecurityStatus] = useState({
    trust: { 
      trust_score: 1.0, 
      trust_level: 'HIGH', 
      security_mode: 'CRYPTO_PLUS_ML', 
      ml_enabled: true 
    },
    policy: { action: 'ALLOW' },
    crypto: { verified: 0, rejected: 0, message_log: [] }
  });

  const [mlEnabled, setMlEnabled] = useState(true);
  const [ipsEnabled, setIpsEnabled] = useState(true);
  const [kafkaConnected, setKafkaConnected] = useState(false);
  const [messageCount, setMessageCount] = useState(0);
  const [lastUpdate, setLastUpdate] = useState(Date.now());
  const [apiConnected, setApiConnected] = useState(false);
  const [v2vAlert, setV2vAlert] = useState(null);
  const [lastAlertTimestamp, setLastAlertTimestamp] = useState(0);
  // Helper function to make authenticated API calls
  const apiCall = async (url, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...options.headers
    };
    
    try {
      const response = await fetch(url, { ...options, headers });
      if (response.status === 401) {
        logout(); // Token expired
        return null;
      }
      return response;
    } catch (error) {
      console.warn('API call failed:', error.message);
      return null;
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await apiCall('http://localhost:5001/api/vehicle-state');
        if (response && response.ok) {
          const data = await response.json();
          setVehicleState(data.vehicle_state);
          setSecurityStatus(data.security_status);
          setKafkaConnected(data.kafka_connected);
          setMessageCount(data.message_count);
          setMlEnabled(data.security_status.trust.ml_enabled);
          setIpsEnabled(data.security_status.ips?.enabled || false);
          
          console.log('V2V Status:', data.security_status.v2v);
          
          // Check for V2V alerts (only show very recent ones)
          if (data.security_status.v2v?.consumer?.recent_alerts?.length > 0) {
            const latestAlert = data.security_status.v2v.consumer.recent_alerts[0];
            const now = Date.now() / 1000; // Current time in seconds
            const alertAge = now - latestAlert.timestamp;
            
            console.log('Alert check:', {
              alertTimestamp: latestAlert.timestamp,
              lastShown: lastAlertTimestamp,
              alertAge: alertAge,
              isNewer: latestAlert.timestamp > lastAlertTimestamp,
              isFresh: alertAge < 30
            });
            
            // Only show alerts that are less than 30 seconds old and newer than last shown
            if (alertAge < 30 && latestAlert.timestamp > lastAlertTimestamp) {
              setV2vAlert(latestAlert);
              setLastAlertTimestamp(latestAlert.timestamp);
            }
          }
          setLastUpdate(Date.now());
          setApiConnected(true);
        } else {
          console.warn('API not responding, using mock data');
          setApiConnected(false);
        }
      } catch (error) {
        console.warn('API connection failed, using mock data:', error.message);
        setApiConnected(false);
        // Use mock data when API is not available
        setVehicleState({
          speed: Math.random() * 60,
          x_position: Math.sin(Date.now() / 1000) * 10,
          y_position: Math.cos(Date.now() / 1000) * 5,
          heading: (Date.now() / 100) % 360,
          steering_angle: Math.sin(Date.now() / 500) * 30,
          brake_pressure: Math.random() * 20
        });
        setLastUpdate(Date.now());
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 100);
    return () => clearInterval(interval);
  }, [v2vAlert, lastAlertTimestamp]);

  const toggleML = async () => {
    if (!isAdmin()) {
      alert('Admin access required to toggle ML mode');
      return;
    }
    
    try {
      const response = await apiCall('http://localhost:5001/api/toggle-ml', {
        method: 'POST',
        body: JSON.stringify({ enabled: !mlEnabled })
      });
      if (response && response.ok) {
        setMlEnabled(!mlEnabled);
      } else {
        console.warn('ML toggle failed - API not available');
        setMlEnabled(!mlEnabled); // Toggle anyway for demo
      }
    } catch (error) {
      console.warn('ML toggle failed:', error.message);
      setMlEnabled(!mlEnabled); // Toggle anyway for demo
    }
  };

  const toggleIPS = async () => {
    if (!isAdmin()) {
      alert('Admin access required to toggle IPS mode');
      return;
    }
    
    try {
      const response = await apiCall('http://localhost:5001/api/toggle-ips', {
        method: 'POST',
        body: JSON.stringify({ enabled: !ipsEnabled })
      });
      if (response && response.ok) {
        setIpsEnabled(!ipsEnabled);
      } else {
        console.warn('IPS toggle failed - API not available');
        setIpsEnabled(!ipsEnabled);
      }
    } catch (error) {
      console.warn('IPS toggle failed:', error.message);
      setIpsEnabled(!ipsEnabled);
    }
  };

  const createVehiclePlot = () => {
    const { x_position, y_position, heading } = vehicleState;
    
    const vehicleTrace = {
      x: [x_position-3, x_position+3, x_position+3, x_position-3, x_position-3],
      y: [y_position-1.5, y_position-1.5, y_position+1.5, y_position+1.5, y_position-1.5],
      fill: 'toself',
      fillcolor: 'blue',
      line: { color: 'darkblue', width: 2 },
      mode: 'lines',
      showlegend: false,
      name: 'Vehicle'
    };

    const headingX = x_position + 5 * Math.cos(heading * Math.PI / 180);
    const headingY = y_position + 5 * Math.sin(heading * Math.PI / 180);
    
    const headingTrace = {
      x: [x_position, headingX],
      y: [y_position, headingY],
      mode: 'lines+markers',
      line: { color: 'red', width: 4 },
      marker: { size: 8, color: 'red' },
      showlegend: false,
      name: 'Heading'
    };

    return {
      data: [vehicleTrace, headingTrace],
      layout: {
        title: 'Vehicle Position',
        xaxis: { 
          range: [x_position-20, x_position+20], 
          title: 'X Position (m)' 
        },
        yaxis: { 
          range: [y_position-10, y_position+10], 
          title: 'Y Position (m)' 
        },
        height: 400,
        showlegend: false,
        images: [{
          source: '/Car.png',
          xref: 'x',
          yref: 'y',
          x: x_position - 0.5,
          y: y_position - 0.9,
          sizex: 11,
          sizey: 11,
          sizing: 'stretch',
          opacity: 1,
          layer: 'above',
          xanchor: 'center',
          yanchor: 'middle'
        }]
      }
    };
  };

  const getTrustColor = (level) => {
    switch (level) {
      case 'HIGH': return 'text-green-500';
      case 'MEDIUM': return 'text-yellow-500';
      case 'LOW': return 'text-orange-500';
      default: return 'text-red-500';
    }
  };

  const getTrustIcon = (level) => {
    switch (level) {
      case 'HIGH': return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'MEDIUM': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'LOW': return <AlertTriangle className="w-5 h-5 text-orange-500" />;
      default: return <AlertTriangle className="w-5 h-5 text-red-500" />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Car className="w-8 h-8 text-blue-600" />
              <h1 className="text-3xl font-bold text-gray-900">Vehicle Digital Twin</h1>
              <span className="text-sm text-gray-500">Phase 5: Behavioral Security</span>
            </div>
            
            {/* User Info & Logout */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm">
                <User className="w-4 h-4" />
                <span>{user?.username}</span>
                <span className={`px-2 py-1 rounded text-xs ${
                  user?.role === 'admin' ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800'
                }`}>
                  {user?.role}
                </span>
              </div>
              <button
                onClick={logout}
                className="flex items-center gap-2 px-3 py-1 text-sm text-gray-600 hover:text-gray-800 border rounded"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              <span>Speed: {vehicleState.speed.toFixed(1)} km/h</span>
            </div>
            <div className="flex items-center gap-2">
              <Target className="w-4 h-4" />
              <span>Position: ({vehicleState.x_position.toFixed(1)}, {vehicleState.y_position.toFixed(1)})</span>
            </div>
            <div className="flex items-center gap-2">
              <RotateCcw className="w-4 h-4" />
              <span>Steering: {vehicleState.steering_angle.toFixed(2)}°</span>
            </div>
          </div>
          
          {/* API Status Indicator */}
          <div className="mt-3 pt-3 border-t border-gray-200">
            <div className="flex items-center gap-2 text-sm">
              {apiConnected ? (
                <><CheckCircle className="w-4 h-4 text-green-500" /><span className="text-green-600">API Connected</span></>
              ) : (
                <><AlertTriangle className="w-4 h-4 text-orange-500" /><span className="text-orange-600">API Disconnected - Using Mock Data</span></>
              )}
            </div>
          </div>
        </div>

        {/* Security Status */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-semibold">Security Status</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-3">
              {getTrustIcon(securityStatus.trust.trust_level)}
              <div>
                <div className={`font-semibold ${getTrustColor(securityStatus.trust.trust_level)}`}>
                  Trust: {securityStatus.trust.trust_score.toFixed(2)} ({securityStatus.trust.trust_level})
                </div>
                <div className="text-sm text-gray-600">Action: {securityStatus.policy.action}</div>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              {mlEnabled ? <Lock className="w-5 h-5 text-green-500" /> : <Unlock className="w-5 h-5 text-red-500" />}
              <div>
                <div className={`font-semibold ${mlEnabled ? 'text-green-600' : 'text-red-600'}`}>
                  Mode: {securityStatus.trust.security_mode}
                </div>
                <div className="text-sm text-gray-600">ML Detection: {mlEnabled ? 'ON' : 'OFF'}</div>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              {kafkaConnected ? <Wifi className="w-5 h-5 text-green-500" /> : <WifiOff className="w-5 h-5 text-red-500" />}
              <div>
                <div className="font-semibold">
                  Data Source: {kafkaConnected ? 'Kafka SDV' : 'Direct CAN'}
                </div>
                <div className="text-sm text-gray-600">Messages: {messageCount}</div>
              </div>
            </div>
          </div>
        </div>

        {/* ML Toggle Control */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <Target className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-semibold">Security Controls</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* ML Toggle */}
            <div>
              <h3 className="font-medium mb-3">ML Detection (Demo)</h3>
              <div className="flex items-center gap-3 mb-2">
                <label className="flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={mlEnabled}
                    onChange={toggleML}
                    disabled={!isAdmin()}
                    className="sr-only"
                  />
                  <div className={`relative w-11 h-6 rounded-full transition-colors ${
                    mlEnabled ? 'bg-green-600' : 'bg-gray-300'
                  } ${!isAdmin() ? 'opacity-50 cursor-not-allowed' : ''}`}>
                    <div className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${mlEnabled ? 'translate-x-5' : 'translate-x-0'}`} />
                  </div>
                  <span className="ml-3 font-medium">Behavioral ML Detection</span>
                  {!isAdmin() && <span className="ml-2 text-xs text-gray-500">(Admin only)</span>}
                </label>
              </div>
              <div className="text-sm text-gray-600">
                {mlEnabled ? 
                  '✓ Crypto + ML: Detects insider attacks' : 
                  '⚠ Crypto Only: Vulnerable to compromise'
                }
              </div>
            </div>
            
            {/* IPS Toggle */}
            <div>
              <h3 className="font-medium mb-3">Intrusion Prevention</h3>
              <div className="flex items-center gap-3 mb-2">
                <label className="flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ipsEnabled}
                    onChange={toggleIPS}
                    disabled={!isAdmin()}
                    className="sr-only"
                  />
                  <div className={`relative w-11 h-6 rounded-full transition-colors ${
                    ipsEnabled ? 'bg-red-600' : 'bg-gray-300'
                  } ${!isAdmin() ? 'opacity-50 cursor-not-allowed' : ''}`}>
                    <div className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${ipsEnabled ? 'translate-x-5' : 'translate-x-0'}`} />
                  </div>
                  <span className="ml-3 font-medium">Active Control</span>
                  {!isAdmin() && <span className="ml-2 text-xs text-gray-500">(Admin only)</span>}
                </label>
              </div>
              <div className="text-sm text-gray-600">
                {ipsEnabled ? (
                  <div>
                    <div className="font-medium text-red-600">🛡️ IPS ACTIVE</div>
                    <div>Mode: {securityStatus.ips?.mode || 'OFF'}</div>
                    {securityStatus.ips?.policy?.speed_limit && (
                      <div>Speed Limit: {securityStatus.ips.policy.speed_limit} km/h</div>
                    )}
                    {securityStatus.ips?.policy?.steering_limit && (
                      <div>Steering: ±{securityStatus.ips.policy.steering_limit}°</div>
                    )}
                  </div>
                ) : (
                  '📊 IPS OFF: Detection only, no control'
                )}
              </div>
            </div>
          </div>
        </div>

        {/* V2V Status */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <Wifi className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-semibold">V2V Communication</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h3 className="font-medium mb-2">Alert Publisher</h3>
              <div className="text-sm text-gray-600">
                <div>Status: {securityStatus.v2v?.publisher?.kafka_available ? '🟢 Connected' : '🔴 Offline'}</div>
                <div>Last Alert: {securityStatus.v2v?.publisher?.last_alert > 0 ? 
                  new Date(securityStatus.v2v.publisher.last_alert * 1000).toLocaleTimeString() : 'None'}</div>
              </div>
            </div>
            
            <div>
              <h3 className="font-medium mb-2">Alert Consumer</h3>
              <div className="text-sm text-gray-600">
                <div>Mode: {securityStatus.v2v?.consumer?.security_mode === 'HEIGHTENED' ? '🟡 Heightened' : '🟢 Normal'}</div>
                <div>Alerts Received: {securityStatus.v2v?.consumer?.alerts_received || 0}</div>
              </div>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">ECU Commands</h2>
          <div className="grid grid-cols-2 md:grid-cols-7 gap-3">
            <button
              onClick={() => {
                // Send direct CAN message with correct steering format
                const steering_angle = 5.0; // +5 degrees right
                const angle_int = Math.floor((steering_angle + 45) * 10); // Convert to CAN format
                const data = [Math.floor(angle_int / 256), angle_int % 256, 0, 0, 0, 0, 0, 0];
                fetch('http://localhost:5001/api/send-can', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ can_id: 0x120, data })
                }).catch(e => console.warn('CAN message failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Turn Left
            </button>
            <button
              onClick={() => {
                // Send direct CAN message with correct steering format
                const steering_angle = -5.0; // -5 degrees left
                const angle_int = Math.floor((steering_angle + 45) * 10); // Convert to CAN format
                const data = [Math.floor(angle_int / 256), angle_int % 256, 0, 0, 0, 0, 0, 0];
                fetch('http://localhost:5001/api/send-can', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ can_id: 0x120, data })
                }).catch(e => console.warn('CAN message failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <ArrowRight className="w-4 h-4" />
              Turn Right
            </button>
            <button
              onClick={() => {
                fetch('http://localhost:5001/api/ecu-command', { 
                  method: 'POST', 
                  headers: { 'Content-Type': 'application/json' }, 
                  body: JSON.stringify({ speed_delta: 0.2 }) 
                }).catch(e => console.warn('ECU command failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <ArrowUp className="w-4 h-4" />
              Speed Up
            </button>
            <button
              onClick={() => {
                fetch('http://localhost:5001/api/ecu-command', { 
                  method: 'POST', 
                  headers: { 'Content-Type': 'application/json' }, 
                  body: JSON.stringify({ speed_delta: -0.2 }) 
                }).catch(e => console.warn('ECU command failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition-colors"
            >
              <ArrowDown className="w-4 h-4" />
              Speed Down
            </button>
            <button
              onClick={() => {
                // Send brake CAN message (0x140)
                const brake_pressure = 50.0; // 50% brake pressure
                const pressure_int = Math.floor(brake_pressure * 10);
                const data = [Math.floor(pressure_int / 256), pressure_int % 256, 0, 0, 0, 0, 0, 0];
                fetch('http://localhost:5001/api/send-can', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ can_id: 0x140, data })
                }).catch(e => console.warn('CAN message failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
            >
              <AlertTriangle className="w-4 h-4" />
              Brake
            </button>
            <button
              onClick={() => {
                // Send 0% brake pressure to release brake
                const brake_pressure = 0.0;
                const pressure_int = Math.floor(brake_pressure * 10);
                const data = [Math.floor(pressure_int / 256), pressure_int % 256, 0, 0, 0, 0, 0, 0];
                fetch('http://localhost:5001/api/send-can', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ can_id: 0x140, data })
                }).catch(e => console.warn('CAN message failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors"
            >
              <CheckCircle className="w-4 h-4" />
              Release Brake
            </button>
            <button
              onClick={() => {
                fetch('http://localhost:5001/api/ecu-command', { 
                  method: 'POST', 
                  headers: { 'Content-Type': 'application/json' }, 
                  body: JSON.stringify({ reset: true }) 
                }).catch(e => console.warn('ECU command failed:', e.message));
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Reset (30km/h, 0°)
            </button>
          </div>
        </div>

        {/* Vehicle Visualization */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <Plot {...createVehiclePlot()} style={{ width: '100%' }} />
        </div>

        {/* Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
          {[
            { label: 'Speed', value: `${vehicleState.speed.toFixed(1)} km/h`, icon: Activity },
            { label: 'X Position', value: `${vehicleState.x_position.toFixed(1)} m`, icon: Target },
            { label: 'Y Position', value: `${vehicleState.y_position.toFixed(1)} m`, icon: Target },
            { label: 'Heading', value: `${vehicleState.heading.toFixed(2)}°`, icon: RotateCcw },
            { label: 'Brake Pressure', value: `${vehicleState.brake_pressure.toFixed(1)}%`, icon: AlertTriangle },
            { label: 'Trust Score', value: securityStatus.trust.trust_score.toFixed(2), icon: Shield }
          ].map((metric, index) => (
            <div key={index} className="bg-white rounded-lg shadow-sm p-4">
              <div className="flex items-center gap-2 mb-2">
                <metric.icon className="w-4 h-4 text-gray-600" />
                <span className="text-sm text-gray-600">{metric.label}</span>
              </div>
              <div className="text-lg font-semibold">{metric.value}</div>
            </div>
          ))}
        </div>

        {/* Message Log */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h2 className="text-xl font-semibold mb-4">Message Security Log</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left p-2">Timestamp</th>
                  <th className="text-left p-2">CAN ID</th>
                  <th className="text-left p-2">Status</th>
                  <th className="text-left p-2">Comment</th>
                </tr>
              </thead>
              <tbody>
                {(securityStatus.crypto.message_log || []).slice(0, 10).map((msg, index) => (
                  <tr key={index} className={`border-b ${msg.status === 'REJECTED' ? 'bg-red-50' : ''}`}>
                    <td className="p-2">{msg.timestamp}</td>
                    <td className="p-2">{msg.can_id}</td>
                    <td className="p-2">
                      <span className={`px-2 py-1 rounded text-xs ${msg.status === 'REJECTED' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                        {msg.status}
                      </span>
                    </td>
                    <td className="p-2">{msg.reason}</td>
                  </tr>
                ))}
                {(!securityStatus.crypto.message_log || securityStatus.crypto.message_log.length === 0) && (
                  <tr>
                    <td colSpan="4" className="p-4 text-center text-gray-500">No messages logged yet</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* V2V Alert Popup */}
        {v2vAlert && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md mx-4">
              <div className="flex items-center gap-3 mb-4">
                <AlertTriangle className="w-8 h-8 text-red-500" />
                <h2 className="text-xl font-bold text-red-600">V2V Security Alert</h2>
              </div>
              
              <div className="mb-4">
                <p className="text-gray-700 mb-2">
                  <strong>From:</strong> {v2vAlert.sender}
                </p>
                <p className="text-gray-700 mb-2">
                  <strong>Threat:</strong> {v2vAlert.threat_type}
                </p>
                <p className="text-gray-700 mb-2">
                  <strong>Confidence:</strong> {(v2vAlert.confidence * 100).toFixed(0)}%
                </p>
                <p className="text-gray-700">
                  <strong>Time:</strong> {new Date(v2vAlert.timestamp * 1000).toLocaleTimeString()}
                </p>
              </div>
              
              <div className="flex gap-3">
                <button
                  onClick={() => setV2vAlert(null)}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  OK
                </button>
                <button
                  onClick={() => setV2vAlert(null)}
                  className="flex-1 px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
        <div className="text-center text-sm text-gray-500 mt-6">
          Live update @ {new Date(lastUpdate).toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
};

const App = () => {
  return (
    <AuthProvider>
      <AuthenticatedDashboard />
    </AuthProvider>
  );
};

const AuthenticatedDashboard = withAuth(Dashboard);

export default App;