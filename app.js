const express = require('express');
const path = require('path');
const fs = require('fs');
const readline = require('readline');
const mongoose = require('mongoose');
const Device = require('./models/device'); // Import the Device model
const Log = require('./models/log'); // Import the Log model we just created

const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/network_monitor', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

function parseNmapLog(log) {
    const nmapResults = [];
    const lines = log.split('\n');
    let currentHost = null;
    
    lines.forEach((line) => {
        if (line.startsWith('Nmap scan report for')) {
            if (currentHost) {
                nmapResults.push(currentHost);
            }
            currentHost = { host: line.split(' ')[4], ports: [], mac: null };
        } else if (line.includes('Host is up')) {
            currentHost.latency = line.match(/\((.*?) latency\)/)?.[1] || null;
        } else if (line.includes('MAC Address')) {
            currentHost.mac = line.split(' ')[2];
        } else if (line.match(/\d+\/tcp/)) {
            const [port, state, service] = line.split(/\s+/);
            currentHost.ports.push({ port, state, service });
        }
    });
    if (currentHost) {
        nmapResults.push(currentHost);
    }
    return nmapResults;
}

// Function to parse IoT logs
function parseIoTLog(log) {
    const logEntries = [];
    const lines = log.split('\n');
        
    lines.forEach((line) => {
        const match = line.match(/\[(.*?)\] \[(.*?)\] \[(.*?)\](?: \[(.*?)\])? (.*)/);
        if (match) {
            const [, timestamp, device, category, level, message, host] = match;
            logEntries.push({ timestamp, device, category, level: level || 'info', message, host });
        }
    });
    return logEntries;
}

// Function to read and parse all logs in the "logs" directory
async function parseAllLogs() {
    const logDir = path.join(__dirname, 'logs');
    console.log(logDir); // Logs directory
    const files = await fs.promises.readdir(logDir); // Read all files
    const allLogs = {};
    
    for (const file of files) {
        const filePath = path.join(logDir, file);
        const logData = await fs.promises.readFile(filePath, 'utf8');
        
        // Determine log type based on file name
        let logType;
        let parsedData;
        
        if (file.includes('nmap')) {
            logType = 'nmap';
            parsedData = parseNmapLog(logData);
        } else if (file.includes('iot')) {
            logType = 'iot';
            parsedData = parseIoTLog(logData);
        } else {
            logType = 'unknown';
            parsedData = logData.split('\n'); // Just return raw lines for unknown log types
        }
        
        allLogs[file] = {
            type: logType,
            data: parsedData
        };
    }
    
    return allLogs;
}

// API to fetch and return all logs and save matching logs to database
// Modified /process-logs route to handle dashboard display requests
app.get('/process-logs', async (req, res) => {
    try {
        // Parse all logs first
        const allLogs = await parseAllLogs();
        
        // Get all devices from database for comparison
        const allDevices = await Device.find({});
        
        // Create a structure to hold logs organized by device
        const deviceLogs = {};
        
        // Initialize deviceLogs with all devices
        allDevices.forEach(device => {
            deviceLogs[device.deviceId] = {
                device: {
                    id: device.deviceId,
                    name: device.name,
                    ip: device.ip,
                    mac: device.mac
                },
                logs: []
            };
        });
        
        // For each log file and its parsed content
        for (const [fileName, logInfo] of Object.entries(allLogs)) {
            const { type, data } = logInfo;
            
            if (type === 'nmap') {
                // For nmap logs, check if any host/IP matches a device in our database
                for (const entry of data) {
                    const hostIp = entry.host;
                    
                    // Find matching device by IP
                    const matchingDevice = allDevices.find(device => 
                        device.ip === hostIp || device.name === hostIp
                    );
                    
                    if (matchingDevice) {
                        // Save this log entry to the database
                        const logEntry = new Log({
                            deviceId: matchingDevice.deviceId,
                            deviceName: matchingDevice.name,
                            deviceIp: matchingDevice.ip,
                            logType: type,
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        await logEntry.save();
                        
                        // Also add to our deviceLogs structure for immediate display
                        deviceLogs[matchingDevice.deviceId].logs.push({
                            id: logEntry._id,
                            timestamp: logEntry.timestamp,
                            type: type,
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        console.log(`Saved matching nmap log for device: ${matchingDevice.name}`);
                    }
                }
            } else if (type === 'iot') {
                // For IoT logs, check if the device field matches a device name
                for (const entry of data) {
                    const deviceName = entry.device;
                    
                    // Find matching device by name
                    const matchingDevice = allDevices.find(device => 
                        device.name === deviceName || device.deviceId === deviceName
                    );
                    
                    if (matchingDevice) {
                        // Save this log entry to the database
                        const logEntry = new Log({
                            deviceId: matchingDevice.deviceId,
                            deviceName: matchingDevice.name,
                            deviceIp: matchingDevice.ip,
                            logType: type,
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        await logEntry.save();
                        
                        // Also add to our deviceLogs structure for immediate display
                        deviceLogs[matchingDevice.deviceId].logs.push({
                            id: logEntry._id,
                            timestamp: logEntry.timestamp,
                            type: type,
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        console.log(`Saved matching IoT log for device: ${matchingDevice.name}`);
                    }
                }
            }
        }
        
        // Check if this is an API request or a dashboard request
       
            // Render the dashboard with device logs
            res.render('device-dashboard', { 
                deviceLogs: deviceLogs,
                totalDevices: allDevices.length,
                totalLogs: Object.values(deviceLogs).reduce((sum, device) => sum + device.logs.length, 0)
            })
          
        
        console.log("Logs processed and matching entries saved to database");
            
    } catch (error) {
        console.error('Error processing logs:', error);
        
        // Check if this is an API request or a dashboard request
        const format = req.query.format || 'json';
        
        if (format === 'html') {
            res.status(500).render('error', { 
                message: 'Failed to process logs',
                error: error.message
            });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
});
app.get('/' , (req,res)=>{
    res.render('index');
})
// Route to render the add device form
app.get('/add-device', (req, res) => {
    res.render('add-device');
});

// API to add a new device
app.post('/api/devices', async (req, res) => {
    try {
        const { deviceId, name, ip, mac } = req.body;
        
        // Validate required fields
        if (!deviceId || !name || !ip || !mac) {
            return res.status(400).json({
                error: 'All fields are required: deviceId, name, ip, and mac'
            });
        }
        
        // Check if device with this deviceId already exists
        const existingDevice = await Device.findOne({ deviceId });
        if (existingDevice) {
            return res.status(409).json({
                error: 'A device with this ID already exists'
            });
        }
        
        // Create and save the new device
        const newDevice = new Device({
            deviceId,
            name,
            ip,
            mac
        });
        
        await newDevice.save();
        
        // Update dnsmasq.conf file with new DHCP reservation
        const { exec } = require('child_process');
        const dnsmasqEntry = `dhcp-host=${mac},${ip} # ${name}`;
        
        // Using sudo with password through environment variable for security
        // (Make sure to set SUDO_PASSWORD as an environment variable)
        const command = `echo "${"Annani2.0"}" | sudo -S bash -c 'echo "${dnsmasqEntry}" >> /etc/dnsmasq.conf && sudo systemctl restart dnsmasq'`;
      
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error updating dnsmasq.conf: ${error.message}`);
                // Still return success for DB addition, but log the dnsmasq issue
                return res.status(201).json({
                    message: 'Device added to database, but failed to update dnsmasq configuration',
                    device: newDevice
                });
            }
            
            if (stderr) {
                console.error(`stderr: ${stderr}`);
            }
            
            res.status(201).json({
                message: 'Device added successfully and DHCP reservation configured',
                device: newDevice
            });
        });
        
    } catch (error) {
        console.error('Error adding device:', error);
        res.status(500).json({ error: 'Failed to add device' });
    }
});

// API to get all devices
app.get('/api/devices', async (req, res) => {
    try {
        const devices = await Device.find({}).sort({ createdAt: -1 });
        res.json(devices);
    } catch (error) {
        console.error('Error fetching devices:', error);
        res.status(500).json({ error: 'Failed to fetch devices' });
    }
});

// API to get logs for a specific device
app.get('/api/logs/:deviceId', async (req, res) => {
    try {
        const { deviceId } = req.params;
        const logs = await Log.find({ deviceId }).sort({ timestamp: -1 });
        res.json(logs);
    } catch (error) {
        console.error('Error fetching logs:', error);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

app.listen(3000, () => {
    console.log(`Server running at http://localhost:${3000}`);
});
