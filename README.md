# RagerX Reports Parser

In an effort to be the most transparent CryptoNote mining pool, we publish various reports about the pool on our [Reports tab](https://monero.ragerx.lol/reports). All mining pools have the ability to modify share data to the pool operator's benefit, open source or not. RagerX is setting a new standard on fair and provable pool mining rewards. All scripts published here are licensed under the 3-Clause BSD license.

To run these scripts, run the following commands:

```
pip install --user pipenv
git clone https://github.com/ragerxlol/reports-parser.git
cd reports-parser
pipenv install
pipenv run python3 block-reports.py
```

## Block Reports

For every block the pool mines, the pool automatically generates a CSV file with every single share submitted to the pool since the previous block was found (or since the PPLNS round started, whichever is earlier.) We publish the sha256sum of this file so anyone can confirm the same file is served to all users. Download one or several block reports from the pool's reports tab, and place it into the `reports` directory. Files are downloaded with the `.csv.xz` format, which you can optionally decompress with `unxz`. If you do not decompress the file, this script will still be able to read its contents.

The file is sorted with newest shares first starting when the block was mined. The file has the following format and column definitions:

```
user_hash,time,difficulty,running_total,pplns,this_block
16ab54562ad0416d,1575701012,500000,500000,y,y
19cd571968994a9c,1575701011,500000,1000000,y,y
```

* `user_hash` is equal to `keccak256(username + salt).substring(0, 16)`
* `time` is the unix timestamp the share was submitted
* `difficulty` is the difficulty of the submitted share
* `running_total` is the sum of the difficulty for this share and all shares preceding it (higher timestamp)
* `pplns` is either `y` or `n` indicating if this share was part of the PPLNS window
* `this_block` is either `y` or `n` indicating if this share was found after the previous pool block's timestamp

We use the hash of the username and salt in order to anonymize the share data while allowing users to identify which shares belong to them. The salt is randomly assigned to each user upon registration and can be obtained on the pool's reports tab. You can have this script automatically identify your shares by writing your username and salt into `reports/users.txt`. Make sure to write your username with the exact same uppercase / lowercase letters that you used to register. For example:

```
mosu OiFjz9cM3E4=
another_user xRDqNlhwb2c=
```

Note: If you want to publicly share your username + salt, edit `users.txt` and send a PR to this repo.

Next run the `block-reports.py` script with:

```
pipenv run python3 block-reports.py
```

The script will loop through every block report in the `reports` directory, get the block header from an independent explorer API, process the information in the CSV file, and finally write the results to a file with `-results.txt` appended to it. Only block reports that have not been process previously will be read. To process a block report again, simply remove the `-results.txt` file and run the script again.

The following output is an example of processing the file `RagerX-block-report-2-1983466.csv` with user `mosu` deanonymized:

```
Height: 1983466
Timestamp: 1575700998
Difficulty: 103927961287
Effort: 13.49%
PPLNS factor: N = 0.6860068472633273
Block reward: 2.107457359846
Pool fee: 3.5%

Pool
Share percentage: 100.0%
Reward: 2.033696352251
Total PPLNS shares: 185636
Total PPLNS hashes: 71295293065
Total block shares: 30054
Total block hashes: 14018184150
Average hashrate (PPLNS): 127417.46 H/s
Average hashrate (block): 610096.36 H/s

Anonymous Users
Share percentage: 94.53363719334618%
Reward: 1.922527131251
Total PPLNS shares: 162649
Total PPLNS hashes: 67398033682
Total block shares: 30054
Total block hashes: 14018184150
Average hashrate (PPLNS): 120452.36 H/s
Average hashrate (block): 610096.36 H/s

mosu
Share percentage: 5.4663628066538195%
Reward: 0.111169220999
Total PPLNS shares: 22987
Total PPLNS hashes: 3897259383
Total block shares: 0
Total block hashes: 0
Average hashrate (PPLNS): 7343.73 H/s
Average hashrate (block): 0 H/s
```

The first section contains general information:

* `Height` is the block height of this report
* `Timestamp` is the unix time this block was found
* `Difficulty` is the target difficulty for this block
* `Effort` is the number of hashes submitted to the pool since the previous pool block divided by the block's difficulty
* `PPLNS factor` is the multiplier of the block's difficulty used in the PPLNS calculation. This will always be close to `2`, except in the above case where there were not enough shares submitted to reach a value of `2`.
* `Block reward` is the amount of coins generated in the coinbase transaction.
* `Pool fee` is the pool's fee

The remaining sections contains information derived from the raw share data relating to the pool overall (all shares), anonymous users (any user not present in `users.txt`), and deanonymized users:

* `Share percentage` is the percentage of shares this user submitted in the PPLNS round. For the pool section, it will always be 100%.
* `Reward` is the amount of coins rewarded to this user. For the pool section, it will always be the block reward minus pool fee.
* `Total PPLNS shares` is the number of shares submitted by this user during the PPLNS round.
* `Total PPLNS hashes` is the number of shares multiplied by their difficulty submitted by this user during the PPLNS round.
* `Total block shares` is the number of shares submitted by this user since the previous pool block.
* `Total block hashes` is the number of shares multiplied by their difficulty submitted by this user since the previous pool block.
* `Average hashrate (PPLNS)` is the calulated hashrate of this user from any shares submitted during the PPLNS round.
* `Average hashrate (block)` is the calulated hashrate of this user from any shares submitted since the previous pool block.

Allowing any user to independently calculate the above information lets them see that their hashrate and payout information as reported by the pool aligns with the raw share data. Below are examples of how a pool might cheat their users, and how RagerX's block reports combats this:

*Case 1: The pool discards some legitimate user shares in order to pay miners less.*

Solution: Since this script calculates your hashrate from your shares, if the pool discarded some of your shares your hashrate would appear less than the miner reports.

*Case 2: The pool inflates your hashrate to make the miner seem faster than it is.*

Solution: Since the block reports show everyone's shares, the average of block efforts would end up being much higher than 100%.

*Case 3: The pool has ghost miners that submit fake shares in order to pay miners less.*

Solution: Since fake shares could never find a block, the average of block efforts would end up being much higher than 100%.

*Case 4: The pool mines to a different address X% of the time in order to not share the rewards with miners.*

Solution: Since legitimate shares would be used to mine blocks not reported by the pool, the average of block efforts would end up being much higher than 100%.

### Conclusion

The main reason that the pool cannot fake data is that by altering shares, the block effort would be affected. Note that a single block will have a variable effort, but the average of about 1,000 or more blocks will always converge to 100%. Additionally, miners can verify all their shares are present in this file, as well as all the pool's shares. If some shares were missing, the calculated hashrate would not match what the miner displays, or the miner's reward would not match what is paid out.

If you have any improvements or questions about how this script works, please feel free to reach out to us. Over time, more scripts will be developed to keep RagerX the most transparent CryptoNote mining pool possible.

Pool mining address: `4AAocFHiPAxNqBgVg4q3PiHAFBvugGk7ULhuHzVC5GRXX2mWxYoCy4n4VE5Ya9AnDYAK5yaF5SvJ5PnyvpD9NrBEEUFJ7M5`

Pool viewkey: `3f8398e86a5e43a8e6ea4c8e1ee760cec194e7dd213edcc99f6b2bcc43528405`
