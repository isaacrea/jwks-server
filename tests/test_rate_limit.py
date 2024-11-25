import requests
import threading

NUM_REQUESTS = 15
USERNAME = ''  # Test username
PASSWORD = ''  # Test password
URL = 'http://127.0.0.1:8080/auth'

success_count = 0
rate_limited_count = 0
other_errors = 0


def send_request():
    global success_count, rate_limited_count, other_errors
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    try:
        response = requests.post(URL, json=data)
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            rate_limited_count += 1
        else:
            other_errors += 1
        print(f'Status Code: {response.status_code}')
    except Exception as e:
        other_errors += 1
        print(f'Error: {e}')


threads = []

for i in range(NUM_REQUESTS):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print(f'\nTotal Requests: {NUM_REQUESTS}')
print(f'Successful Requests: {success_count}')
print(f'Rate Limited Requests: {rate_limited_count}')
print(f'Other Errors: {other_errors}')
