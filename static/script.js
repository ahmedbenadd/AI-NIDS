// Connect to Socket.IO Server
const socket = io();

// DOM Elements
const statusBadge = document.getElementById('connection-status');
const pulseDot = document.querySelector('.pulsing-dot');
const totalPacketsEl = document.getElementById('total-packets');
const normalPacketsEl = document.getElementById('normal-packets');
const attackPacketsEl = document.getElementById('attack-packets');
const threatRatioEl = document.getElementById('threat-ratio');
const packetLog = document.getElementById('packet-log');
const attackLog = document.getElementById('attack-log');

// State
let stats = {
    total: 0,
    normal: 0,
    attack: 0
};

// Chart.js Configuration
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Outfit', sans-serif";

const ctx = document.getElementById('liveChart').getContext('2d');
const gradientNormal = ctx.createLinearGradient(0, 0, 0, 400);
gradientNormal.addColorStop(0, 'rgba(16, 185, 129, 0.5)');
gradientNormal.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

const gradientAttack = ctx.createLinearGradient(0, 0, 0, 400);
gradientAttack.addColorStop(0, 'rgba(239, 68, 68, 0.5)');
gradientAttack.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

const chartConfig = {
    type: 'line',
    data: {
        labels: Array(30).fill(''),
        datasets: [
            {
                label: 'Normal Traffic',
                data: Array(30).fill(0),
                borderColor: '#10b981',
                backgroundColor: gradientNormal,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0
            },
            {
                label: 'Attack Traffic',
                data: Array(30).fill(0),
                borderColor: '#ef4444',
                backgroundColor: gradientAttack,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 0 // Disable internal animation for real-time performance
        },
        interaction: {
            mode: 'index',
            intersect: false,
        },
        scales: {
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)',
                    drawBorder: false
                }
            },
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)',
                    drawBorder: false
                },
                beginAtZero: true
            }
        },
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    usePointStyle: true,
                    boxWidth: 8
                }
            }
        }
    }
};

const liveChart = new Chart(ctx, chartConfig);

// Chart Update Batches (to prevent UI freezing on high throughput)
let currentSecondNormal = 0;
let currentSecondAttack = 0;

setInterval(() => {
    // Shift data
    const labels = liveChart.data.labels;
    const normalData = liveChart.data.datasets[0].data;
    const attackData = liveChart.data.datasets[1].data;

    labels.push(new Date().toLocaleTimeString('en-US', { hour12: false, hour: "numeric", minute: "numeric", second: "numeric" }));
    labels.shift();

    normalData.push(currentSecondNormal);
    normalData.shift();

    attackData.push(currentSecondAttack);
    attackData.shift();

    liveChart.update();

    // Reset counters for next second
    currentSecondNormal = 0;
    currentSecondAttack = 0;
}, 1000);

// Socket.IO Events
socket.on('connect', () => {
    statusBadge.textContent = 'Engine Active';
    statusBadge.classList.remove('disconnected');
    pulseDot.style.backgroundColor = '#10b981';
    pulseDot.style.boxShadow = '0 0 10px #10b981';
});

socket.on('disconnect', () => {
    statusBadge.textContent = 'Engine Disconnected';
    statusBadge.classList.add('disconnected');
    pulseDot.style.backgroundColor = '#ef4444';
    pulseDot.style.boxShadow = '0 0 10px #ef4444';
});

// Handling incoming real-time packets
socket.on('new_packet', (packet) => {
    // 1. Update Stats
    stats.total++;
    const isAttack = packet.prediction === 'ATTACK';
    
    if (isAttack) {
        stats.attack++;
        currentSecondAttack++;
    } else {
        stats.normal++;
        currentSecondNormal++;
    }

    // 2. Update UI Counters
    totalPacketsEl.textContent = stats.total.toLocaleString();
    normalPacketsEl.textContent = stats.normal.toLocaleString();
    attackPacketsEl.textContent = stats.attack.toLocaleString();
    
    const ratio = ((stats.attack / stats.total) * 100).toFixed(1);
    threatRatioEl.textContent = `${ratio}%`;

    // 3. Update Table
    const row = document.createElement('tr');
    row.className = 'packet-row';
    
    const badgeClass = isAttack ? 'verdict-attack' : 'verdict-normal';
    
    row.innerHTML = `
        <td>${packet.timestamp}</td>
        <td>${packet.src_ip}</td>
        <td>${packet.dst_ip}</td>
        <td>${packet.protocol}</td>
        <td>${packet.service}</td>
        <td>${packet.bytes}</td>
        <td><span class="verdict-badge ${badgeClass}">${packet.prediction}</span></td>
    `;
    
    // Add to all traffic log
    packetLog.insertBefore(row.cloneNode(true), packetLog.firstChild);
    
    // Keep maximum 50 rows to prevent memory issues
    if (packetLog.children.length > 50) {
        packetLog.removeChild(packetLog.lastChild);
    }
    
    // Add exclusively to attack log
    if (isAttack) {
        attackLog.insertBefore(row.cloneNode(true), attackLog.firstChild);
        if (attackLog.children.length > 50) {
            attackLog.removeChild(attackLog.lastChild);
        }
    }
});
