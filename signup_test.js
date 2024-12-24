import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
    vus: 40, // Number of Virtual Users
    duration: '59s', // Test duration
};

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomPhoneNumber() {
    let phoneNumber = '';
    for (let i = 0; i < 10; i++) {
        phoneNumber += getRandomInt(0, 9).toString();
    }
    return phoneNumber;
}

// Generate a more random dummy user with a larger randomId and phone number
function generateDummyUser() {
    const randomId = getRandomInt(100000, 999999); // Larger range for randomId
    const randomString = getRandomString(10); // Random string for more variability
    return {
        name: `user${randomId}${randomString}`,
        username: `user${randomId}${randomString}username`,
        password: 'Raghav@111',
        confirmPassword: 'Raghav@111',
        email: `user${randomId}${randomString}@test.com`,
        phone: generateRandomPhoneNumber(), // More random phone number
    };
}

export default function () {
    const user = generateDummyUser();

    // Prepare the payload (data as JSON)
    const payload = JSON.stringify({
        name: user.name,
        username: user.username,
        password: user.password,
        confirmPassword: user.confirmPassword,
        email: user.email,
        phone: user.phone,
    });

    // Define the headers (Content-Type should be application/json)
    const headers = {
        'Content-Type': 'application/json',
    };

    // Make the POST request to the signup endpoint
    const res = http.post('http://localhost:7000/api/v1/auth/signup', payload, { headers });

   

    // Validate the response
    check(res, {
        'is status 201': (r) => r.status === 201,
        'user registered': (r) => r.json('message') === 'User registered. Please verify your email.',
    });

    sleep(1); // Simulate a pause between requests
}
