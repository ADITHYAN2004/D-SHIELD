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

// Function to parse Firewall logs
function parseFirewallLog(log) {
    const logEntries = [];
    const lines = log.split('\n');
    
    lines.forEach((line) => {
        if (!line.trim()) return; // Skip empty lines
        
        // Parse format: 04/02-08:30:12.456789 [**] [200001] Allow Web Access to Gateway [**] SRC=192.168.1.50 DST=192.168.2.1 PROTO=TCP SPT=56789 DPT=80
        const timestampMatch = line.match(/^(\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})/);
        const alertIdMatch = line.match(/\[\*\*\] \[(\d+)\] (.*?) \[\*\*\]/);
        
        if (timestampMatch && alertIdMatch) {
            const timestamp = timestampMatch[1];
            const alertId = alertIdMatch[1];
            const alertMessage = alertIdMatch[2];
            
            // Extract network information
            const sourceIp = line.match(/SRC=(\S+)/)?.[1] || null;
            const destIp = line.match(/DST=(\S+)/)?.[1] || null;
            const protocol = line.match(/PROTO=(\S+)/)?.[1] || null;
            const sourcePort = line.match(/SPT=(\d+)/)?.[1] || null;
            const destPort = line.match(/DPT=(\d+)/)?.[1] || null;
            const flags = line.match(/FLAGS:(\S+)/)?.[1] || null;
            
            logEntries.push({
                timestamp,
                alertId,
                alertMessage,
                sourceIp,
                destIp,
                protocol,
                sourcePort,
                destPort,
                flags,
                raw: line
            });
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
        } else if (file.includes('firewall')) {
            logType = 'firewall';
            parsedData = parseFirewallLog(logData);
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
            } else if (type === 'firewall') {
                // For firewall logs, check if source or destination IP matches a device IP
                for (const entry of data) {
                    const sourceIp = entry.sourceIp;
                    const destIp = entry.destIp;
                    
                    // Find matching device by IP (either as source or destination)
                    const matchingSourceDevice = allDevices.find(device => device.ip === sourceIp);
                    const matchingDestDevice = allDevices.find(device => device.ip === destIp);
                    
                    // Process source device if found
                    if (matchingSourceDevice) {
                        // Save this log entry to the database
                        const logEntry = new Log({
                            deviceId: matchingSourceDevice.deviceId,
                            deviceName: matchingSourceDevice.name,
                            deviceIp: matchingSourceDevice.ip,
                            logType: 'firewall-source',
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        await logEntry.save();
                        
                        // Also add to our deviceLogs structure for immediate display
                        deviceLogs[matchingSourceDevice.deviceId].logs.push({
                            id: logEntry._id,
                            timestamp: logEntry.timestamp,
                            type: 'firewall-source',
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        console.log(`Saved matching firewall source log for device: ${matchingSourceDevice.name}`);
                    }
                    
                    // Process destination device if found and different from source
                    if (matchingDestDevice && (!matchingSourceDevice || matchingDestDevice.deviceId !== matchingSourceDevice.deviceId)) {
                        // Save this log entry to the database
                        const logEntry = new Log({
                            deviceId: matchingDestDevice.deviceId,
                            deviceName: matchingDestDevice.name,
                            deviceIp: matchingDestDevice.ip,
                            logType: 'firewall-destination',
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        await logEntry.save();
                        
                        // Also add to our deviceLogs structure for immediate display
                        deviceLogs[matchingDestDevice.deviceId].logs.push({
                            id: logEntry._id,
                            timestamp: logEntry.timestamp,
                            type: 'firewall-destination',
                            content: entry,
                            sourceFile: fileName
                        });
                        
                        console.log(`Saved matching firewall destination log for device: ${matchingDestDevice.name}`);
                    }
                }
            }
        }
        
        // Check if this is an API request or a dashboard request
        res.render('device-dashboard', { 
            deviceLogs: deviceLogs,
            totalDevices: allDevices.length,
            totalLogs: Object.values(deviceLogs).reduce((sum, device) => sum + device.logs.length, 0)
        });
        
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

// API to get firewall logs summary by device
app.get('/api/firewall-summary', async (req, res) => {
    try {
        // Get counts of different types of alerts for each device
        const firewallLogs = await Log.find({
            logType: { $in: ['firewall-source', 'firewall-destination'] }
        });
        
        // Create summary by device
        const deviceSummary = {};
        
        firewallLogs.forEach(log => {
            const deviceId = log.deviceId;
            const alertMessage = log.content.alertMessage;
            const isAuthorized = !alertMessage.includes('Unauthorized');
            
            if (!deviceSummary[deviceId]) {
                deviceSummary[deviceId] = {
                    deviceName: log.deviceName,
                    deviceIp: log.deviceIp,
                    authorized: 0,
                    unauthorized: 0,
                    total: 0
                };
            }
            
            if (isAuthorized) {
                deviceSummary[deviceId].authorized++;
            } else {
                deviceSummary[deviceId].unauthorized++;
            }
            
            deviceSummary[deviceId].total++;
        });
        
        res.json(deviceSummary);
    } catch (error) {
        console.error('Error generating firewall summary:', error);
        res.status(500).json({ error: 'Failed to generate firewall summary' });
    }
});

app.listen(3000, () => {
    console.log(`Server running at http://localhost:${3000}`);
});