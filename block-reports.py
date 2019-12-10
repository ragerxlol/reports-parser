import os, math, collections, copy, csv, lzma, sha3, requests, re, json

POOL_FEE = 3.5
COIN_UNITS = pow(10, 12)

def calculate_user_hashes(filename):
    user_hashes = {}
    with open(filename, 'r') as users:
        for user in users:
            parts = user.split()

            # each line in users.txt must be in format:
            # username salt
            if len(parts) < 2:
                continue

            username = parts[0]
            salt = parts[1]

            # user_hash is keccak256(username + salt).substring(0, 16)
            user_hash = sha3.keccak_256(str(username+salt).encode('utf-8')).hexdigest()[0:16]

            # store in dict by key user_hash
            user_hashes[user_hash] = username

    return user_hashes

def open_report(filename):
    if filename.endswith('.csv.xz'):
        return lzma.open(filename, mode='rt')
    elif filename.endswith('.csv'):
        return open(filename, 'r')
    else:
        return False

def crunch_report(report, user_hashes):

    # Sum of all shares over time DESC
    running_total = 0

    # Dict that will be used to collect stats for pool, anon users, and known users
    stats_template = {
        'pplns': {
            'timestamp_start': math.inf,
            'timestamp_end': -math.inf,
            'total_shares': 0,
            'total_hashes': 0,
        },
        'block': {
            'timestamp_start': math.inf,
            'timestamp_end': -math.inf,
            'total_shares': 0,
            'total_hashes': 0,
        },
    }

    # Make a copy of the stats template for both pool and anon
    stats = collections.OrderedDict([
        ('_pool', copy.deepcopy(stats_template)),
        ('_anon', copy.deepcopy(stats_template)),
    ])

    # Make a copy of the stats template for all known users
    for username in user_hashes.values():
        stats[username] = copy.deepcopy(stats_template)

    # Open the csv file
    shares = csv.DictReader(report)

    for share in shares:

        # Loop through each share in the CSV file, example share shown below:
        # print(share)
        # { 'user_hash': '19cd571968994a9c', 'time': '1575701011', 'difficulty': '500000', 'running_total': '1544750', 'pplns': 'y', 'this_block': 'y'}

        # Convert some values to Integers
        share['time'] = int(share['time'])
        share['difficulty'] = int(share['difficulty'])
        share['running_total'] = int(share['running_total'])

        # Add to the running total
        running_total += share['difficulty']

        # Check to see that our running total matches up with CSV
        if running_total != share['running_total']:
            print('Error on line {}: Running total does not add up'.format(shares.line_num))
            return

        # Get username, or _anon if unknown
        username = user_hashes.get(share['user_hash'], '_anon')

        # Check if this share is marked as being in the PPLNS round
        if share['pplns'] == 'y':

            # Add stats to _pool dict
            stats['_pool']['pplns']['timestamp_start'] = min(stats['_pool']['pplns']['timestamp_start'], share['time'])
            stats['_pool']['pplns']['timestamp_end']   = max(stats['_pool']['pplns']['timestamp_end'],   share['time'])
            stats['_pool']['pplns']['total_hashes']   += share['difficulty']
            stats['_pool']['pplns']['total_shares']   += 1

            # Add stats to user dict
            stats[username]['pplns']['timestamp_start'] = min(stats[username]['pplns']['timestamp_start'], share['time'])
            stats[username]['pplns']['timestamp_end']   = max(stats[username]['pplns']['timestamp_end'],   share['time'])
            stats[username]['pplns']['total_hashes']   += share['difficulty']
            stats[username]['pplns']['total_shares']   += 1

        # Check if this share is marked as being in the block round
        if share['this_block'] == 'y':

            # Add stats to _pool dict
            stats['_pool']['block']['timestamp_start'] = min(stats['_pool']['block']['timestamp_start'], share['time'])
            stats['_pool']['block']['timestamp_end']   = max(stats['_pool']['block']['timestamp_end'],   share['time'])
            stats['_pool']['block']['total_hashes']   += share['difficulty']
            stats['_pool']['block']['total_shares']   += 1

            # Add stats to user dict
            stats[username]['block']['timestamp_start'] = min(stats[username]['block']['timestamp_start'], share['time'])
            stats[username]['block']['timestamp_end']   = max(stats[username]['block']['timestamp_end'],   share['time'])
            stats[username]['block']['total_hashes']   += share['difficulty']
            stats[username]['block']['total_shares']   += 1

    return stats

def format_results(block_header, stats):
    # These values are from the explorer api
    difficulty = block_header['difficulty']
    height = block_header['height']
    timestamp = block_header['timestamp']
    reward = block_header['reward']
    reward_minus_fee = int(reward * ((100 - POOL_FEE) / 100))
    effort = stats['_pool']['block']['total_hashes'] / difficulty
    pplns_factor = stats['_pool']['pplns']['total_hashes'] / difficulty

    results = ''
    results += 'Height: {}\n'.format(height)
    results += 'Timestamp: {}\n'.format(timestamp)
    results += 'Difficulty: {}\n'.format(difficulty)
    results += 'Effort: {}%\n'.format(round(100 * effort, 2))
    results += 'PPLNS factor: N = {}\n'.format(pplns_factor)
    results += 'Block reward: {}\n'.format(reward / COIN_UNITS)
    results += 'Pool fee: {}%\n'.format(POOL_FEE)

    for username, stat in stats.items():
        if username == '_pool':
            username = 'Pool'
        elif username == '_anon':
            username = 'Anonymous Users'

        # Calculate share percentage in PPLNS round
        share_percentage = stat['pplns']['total_hashes'] / stats['_pool']['pplns']['total_hashes']

        # Calculate earnings
        user_reward = int(share_percentage * reward_minus_fee) / COIN_UNITS

        # Calculate hashrate in during the PPLNS window
        if stat['pplns']['total_shares'] == 0:
            hashrate_pplns = 0
        else:
            hashrate_pplns = stat['pplns']['total_hashes'] / (stat['pplns']['timestamp_end'] - stat['pplns']['timestamp_start'])

        # Calculate hashrate in during the block window
        if stat['block']['total_shares'] == 0:
            hashrate_block = 0
        else:
            hashrate_block = stat['block']['total_hashes'] / (stat['block']['timestamp_end'] - stat['block']['timestamp_start'])

        results += '\n{}\n'.format(username)
        results += 'Share percentage: {}%\nReward: {}\n'.format(100 * share_percentage, user_reward)
        results += 'Total PPLNS shares: {}\nTotal PPLNS hashes: {}\n'.format(stat['pplns']['total_shares'], stat['pplns']['total_hashes'])
        results += 'Total block shares: {}\nTotal block hashes: {}\n'.format(stat['block']['total_shares'], stat['block']['total_hashes'])
        results += 'Average hashrate (PPLNS): {} H/s\nAverage hashrate (block): {} H/s\n'.format(round(hashrate_pplns, 2), round(hashrate_block, 2))

    return results

def write_results(results, filename):
    with open(filename, 'w') as file:
        file.write(results)

def get_block_header_from_explorer(height):
    r = requests.get('http://moneroblocks.info/api/get_block_header/' + height)
    if not r.status_code is 200:
        return False
    try:
        return json.loads(r.text)['block_header']
    except ValueError as e:
        return False

def main():

    # Calculate optional user hashes from reports/users.txt
    # If provided, this will de-anonymize shares in the block reports
    user_hashes = calculate_user_hashes(os.path.join('reports', 'users.txt'))

    # Loop through files in the reports/ directory
    for filename in os.listdir('reports'):

        # Skip any non block report files
        if not filename.startswith('RagerX-block-report'):
            continue

        # Skip files that end with '-results.txt'
        # these files are the result of this program
        if filename.endswith('-results.txt'):
            continue

        # This is the file we will write results to
        results_file = os.path.join('reports', filename + '-results.txt')

        # Check if it already exists, if so don't recreate
        if os.path.isfile(results_file):
            continue

        # Get the block height from the filename
        match = re.match('RagerX\-block\-report\-[\d+]\-(\d+)\.csv', filename)
        if not match:
            print('Cannot parse block height from file: ', filename)
            continue

        height = match.groups()[0]


        # Get the block header from an explorer
        print('Getting block_header for block at height {}'.format(height))
        block_header = get_block_header_from_explorer(height)

        # Attempt to open file, if it's not a valid
        # file extension we will return False
        report = open_report(os.path.join('reports', filename))
        if report is False:
            continue

        # Do the actual calculations
        print('Processing report {}'.format(filename))
        stats = crunch_report(report, user_hashes)

        print('Formatting results')
        results = format_results(block_header, stats)

        print('Writing results')
        write_results(results, results_file)

        # Close the file handle
        report.close()


if __name__ == "__main__":
    main()
