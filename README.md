# Merkle Tree lib

This is an implementation of a merkle tree in Rust. It uses sha256 for hashing.

## NOTES

### Compare to `merkle`

[`merkle`](https://crates.io/crates/merkle) is another merkle tree library with a bit of a different implementation.

```
create merkle tree - big
                        time:   [402.52 µs 403.71 µs 405.01 µs]
                        change: [+0.4355% +0.9470% +1.5179%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe

generate merkle proof - big
                        time:   [335.80 µs 336.19 µs 336.60 µs]
                        change: [-0.0793% +0.2623% +0.6097%] (p = 0.14 > 0.05)
                        No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe
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