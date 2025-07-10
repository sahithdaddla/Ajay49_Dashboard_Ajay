const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');

const PORT = 3939;
const wss = new WebSocket.Server({ port: PORT });

const activeClients = new Map();

wss.on('connection', (ws) => {
  const clientId = uuidv4();
  console.log(`New client connected: ${clientId}`);
  activeClients.set(clientId, ws);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'login') {
        // Broadcast employee details to all connected clients
        const empDetails = {
          type: 'emp_details',
          data: {
            name: data.name,
            email: data.email,
            emp_id: data.emp_id
          }
        };
        
        activeClients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(empDetails));
          }
        });
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  ws.on('close', () => {
    console.log(`Client disconnected: ${clientId}`);
    activeClients.delete(clientId);
  });
});

console.log(`WebSocket server running on ws://44.223.23.145:${PORT}`);
