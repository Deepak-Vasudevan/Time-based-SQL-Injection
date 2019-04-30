import requests as rq
import numpy as np
import statistics as st
import matplotlib.pyplot as plt
import csv
import time as tm


# Generate random ids for web pages
def rand_id():
    return np.random.randint(1, 999)


# Generate safe and vulnerable site list
def site_url(s_list):
    sites = []
    for s_flag in s_list:
        site_id = rand_id()
        page_no = rand_id()
        payload = {'id': site_id}
        if s_flag:
            url = 'http://localhost:5000/vulnerable/' + str(page_no) + '/page'
            sites.append((url, payload, s_flag))
        else:
            url = 'http://localhost:5000/safe/' + str(page_no) + '/page'
            sites.append((url, payload, s_flag))
    return sites


# Check the vulnerability of the sites by modeling the network delay
def site_check(s_url, s_payload, comp_flag):

    nw_resp_time = []
    delay_resp_time = []
    server_status = True

    file_log = 'Injection_testing.log'

    req = rq.get(s_url, params=s_payload)

    for i in range(5):
        req = rq.get(s_url, params=s_payload)
        nw_resp_time.append(req.elapsed.total_seconds())
        server_status = False if (req.status_code > 299) else True   # check if server is active
    avg_nw_delay = round(st.mean(nw_resp_time), 4)

    inj_sleep = round(2 * avg_nw_delay)   # introduce a delay corresponding to twice the avg. network delay

    if server_status:
        for j in range(1, 6):
            inj_payload = {'id': 'SLEEP(' + str(inj_sleep) + ')'}
            req = rq.get(s_url, params=inj_payload)
            req.raise_for_status()
            delay_resp_time.append(round(req.elapsed.total_seconds(), 4))
            with open(file_log, 'a') as f:
                f.write(str(delay_resp_time[j-1]) + '\t' + str(req.status_code) + '\t'
                        + str(avg_nw_delay) + '\t' + req.url + '\t' + req.text + '\n')

        check_flag = 1 if (st.mean(delay_resp_time) - avg_nw_delay >= inj_sleep) else 0
    else:
        check_flag = 0
        with open(file_log, 'a') as f:
            f.write('NaN \t Timeout \t NaN \t' + req.url + '\t' + 'Server Unavailable')

    return [req.url, check_flag, comp_flag]


# Evaluation of the number of false positives
def test_eval(site_results):
    transpose_res = list(zip(*site_results))
    return sum(list(set(transpose_res[1]) - set(transpose_res[2])))


# Plot evaluation
def test_plots(n, file_log):
    x = []
    with open(file_log, 'r') as f_csv:
        next(f_csv)
        plot_data = csv.reader(f_csv, delimiter='\t')
        for row in plot_data:
            x.append(float(row[0]))
    delay_map = np.reshape(x, (n, 5))

    time_range = range(delay_map.shape[1])

    for i in range(delay_map.shape[0]):
        plt.plot(time_range, delay_map[i, :])
    plt.xlabel('Induced Delay - 2*Network Delay (s)')
    plt.xticks(np.arange(5), ('Req_1', 'Req_2', 'Req_3', 'Req_4', 'Req_5'))
    plt.ylabel('Observed Response (s)')
    plt.title('SQL Injection - URL profiles')
    plt.show()


if __name__ == '__main__':
    page_results = []
    test_duration = []
    avg_safe_url_response = []
    avg_vuln_url_response = []

    page_count = int(input("Enter the number of pages to test: "))
    page_list = np.random.randint(2, size=(page_count,))

    pages = site_url(page_list)

    # Generating the log
    with open('Injection_testing.log', 'w') as f:
        f.write('Response_time \t Status_code \t Avg_network_delay \t URL \t Content\n')

    for (page_url, page_payload, page_flag) in pages:
        start_time = tm.time()
        page_results.append(site_check(page_url, page_payload, page_flag))
        end_time = tm.time()
        test_duration.append(end_time - start_time)
        if page_flag:
            avg_vuln_url_response.append(end_time - start_time)
        else:
            avg_safe_url_response.append(end_time - start_time)

    # Evaluation results
    false_positives = test_eval(page_results) / page_count

    print('False Positives: ' + str(false_positives))

    print('Average test execution time for safe urls: ' + str(st.mean(avg_safe_url_response)))
    print('Average test execution time for vulnerable urls: ' + str(st.mean(avg_vuln_url_response)))

    test_plots(page_count, 'Injection_testing.log')
