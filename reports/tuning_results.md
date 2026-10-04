# Tuning results

Random search, 25 configurations, each fitted on a 25% class-stratified subsample of train. Early stopping (30 rounds, aucpr) and scoring use the full validation split.

## All configurations, best first

| # | depth | lr | subsample | colsample | min child | lambda | weighting | trees | val PR-AUC | worst class | its recall |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 11 | 6 | 0.3 | 0.7 | 0.6 | 10 | 10.0 | scale_pos_weight | 81 | 0.99992 | Bot | 0.7054 |
| 15 | 12 | 0.3 | 0.8 | 1.0 | 20 | 10.0 | class_sqrt | 86 | 0.99991 | Bot | 0.6973 |
| 3 | 6 | 0.3 | 0.9 | 0.6 | 10 | 50.0 | scale_pos_weight | 171 | 0.99989 | Bot | 0.7108 |
| 1 | 4 | 0.3 | 0.6 | 0.9 | 10 | 0.1 | none | 190 | 0.99988 | Bot | 0.6838 |
| 14 | 10 | 0.2 | 0.9 | 0.6 | 5 | 1.0 | none | 106 | 0.99988 | Bot | 0.6919 |
| 10 | 8 | 0.1 | 0.7 | 1.0 | 5 | 0.1 | class_sqrt | 125 | 0.99988 | Bot | 0.7162 |
| 18 | 4 | 0.2 | 0.9 | 0.9 | 10 | 50.0 | scale_pos_weight | 211 | 0.99988 | Bot | 0.7027 |
| 7 | 10 | 0.03 | 1.0 | 0.7 | 20 | 5.0 | class_sqrt | 232 | 0.99987 | Bot | 0.6973 |
| 22 | 12 | 0.3 | 0.7 | 0.6 | 5 | 1.0 | class_sqrt | 44 | 0.99987 | Bot | 0.7135 |
| 21 | 8 | 0.3 | 0.7 | 0.9 | 1 | 5.0 | class_sqrt | 86 | 0.99987 | Bot | 0.7081 |
| 8 | 6 | 0.03 | 0.6 | 1.0 | 3 | 5.0 | none | 779 | 0.99986 | Bot | 0.6811 |
| 19 | 12 | 0.03 | 0.6 | 1.0 | 20 | 5.0 | class_sqrt | 220 | 0.99985 | Bot | 0.6919 |
| 6 | 12 | 0.1 | 0.6 | 1.0 | 10 | 50.0 | none | 298 | 0.99982 | Bot | 0.6838 |
| 16 | 10 | 0.1 | 0.7 | 0.6 | 20 | 10.0 | none | 100 | 0.99980 | Bot | 0.6703 |
| 20 | 8 | 0.03 | 0.8 | 0.8 | 3 | 10.0 | none | 222 | 0.99978 | Bot | 0.5946 |
| 13 | 10 | 0.1 | 0.6 | 0.6 | 20 | 5.0 | none | 67 | 0.99977 | Bot | 0.6514 |
| 24 | 8 | 0.1 | 0.7 | 0.5 | 3 | 50.0 | none | 52 | 0.99966 | Bot | 0.3000 |
| 4 | 4 | 0.05 | 0.9 | 0.7 | 5 | 1.0 | none | 224 | 0.99964 | Bot | 0.3351 |
| 2 | 4 | 0.05 | 0.7 | 0.9 | 20 | 0.1 | class_sqrt | 142 | 0.99963 | Bot | 0.5297 |
| 9 | 6 | 0.03 | 0.9 | 0.7 | 10 | 5.0 | none | 200 | 0.99955 | Bot | 0.3351 |
| 17 | 4 | 0.03 | 0.7 | 1.0 | 3 | 10.0 | class_sqrt | 214 | 0.99955 | Bot | 0.3784 |
| 0 | 4 | 0.03 | 0.8 | 0.6 | 3 | 1.0 | class_sqrt | 187 | 0.99949 | Bot | 0.2973 |
| 23 | 12 | 0.03 | 1.0 | 0.7 | 10 | 0.1 | none | 49 | 0.99946 | Bot | 0.4595 |
| 5 | 8 | 0.03 | 0.6 | 0.8 | 1 | 5.0 | scale_pos_weight | 90 | 0.99941 | Bot | 0.5486 |
| 12 | 12 | 0.05 | 0.8 | 0.5 | 3 | 0.1 | scale_pos_weight | 16 | 0.99893 | Bot | 0.6946 |

## Weighting options compared

| weighting | configs | mean val PR-AUC | best val PR-AUC | mean worst-class recall | best worst-class recall |
|---|---|---|---|---|---|
| none | 11 | 0.99974 | 0.99988 | 0.5533 | 0.6919 |
| scale_pos_weight | 5 | 0.99961 | 0.99992 | 0.6724 | 0.7108 |
| class_sqrt | 9 | 0.99977 | 0.99991 | 0.6033 | 0.7162 |

## Selection

Best validation PR-AUC: 0.99992
Configurations within 0.002 of the best: [2, 0, 1, 18, 17, 4, 11, 3, 9, 8, 24, 21, 5, 10, 20, 13, 16, 14, 7, 12, 22, 23, 15, 19, 6]
Tie rule: the simplest wins, meaning smaller max_depth, then fewer trees, then none over scale_pos_weight over class_sqrt.

Chosen configuration #2: depth 4, lr 0.05, subsample 0.7, colsample 0.9, min child weight 20, lambda 0.1, weighting class_sqrt
