import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:5000/api',
});

export const startScan = async (domain, scanType) => {
    const response = await api.post('/scan/start', { domain, scan_type: scanType });
    return response.data;
};

export const getScanStatus = async (scanId) => {
    const response = await api.get(`/scan/status/${scanId}`);
    return response.data;
};

export const getScanLogs = async (scanId) => {
    const response = await api.get(`/scan/logs/${scanId}`);
    return response.data;
};

export const getResults = async () => {
    const response = await api.get('/results');
    return response.data;
}

export const getResultDetail = async (filename) => {
    const response = await api.get(`/results/${filename}`);
    return response.data;
}

export default api;
