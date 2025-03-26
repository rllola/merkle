# Merkle Tree lib

This is an implementation of a merkle tree in Rust. It uses sha256 for hashing.

## NOTES

### Compare to `merkle`

[`merkle`](https://crates.io/crates/merkle) is another merkle tree library with a bit of a different implementation.

```
create merkle tree - big
                        time:   [439.61 µs 441.34 µs 443.25 µs]
                        change: [-2.0798% -0.8046% +0.5165%] (p = 0.23 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  7 (7.00%) high mild
  4 (4.00%) high severe

generate merkle proof - big
                        time:   [143.74 µs 145.06 µs 146.50 µs]
                        change: [-8.6987% -6.2184% -3.7437%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 7 outliers among 100 measurements (7.00%)
  2 (2.00%) low mild
  4 (4.00%) high mild
  1 (1.00%) high severe
```

```
MerkleTree::from_vec - big                                                                            
                        time:   [313.09 µs 315.15 µs 317.41 µs]
                        change: [-2.5448% -1.3958% -0.2323%] (p = 0.02 < 0.05)
                        Change within noise threshold.
Found 7 outliers among 100 measurements (7.00%)
  1 (1.00%) low mild
  4 (4.00%) high mild
  2 (2.00%) high severe

MerkleTree::gen_proof - big                                                                            
                        time:   [466.00 µs 471.24 µs 476.96 µs]
                        change: [-7.2742% -5.0715% -2.6917%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) high mild
  3 (3.00%) high severe
```

Runned from laptop.