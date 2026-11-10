
## Cleaning decisions

- Column names are stripped of leading and trailing spaces.
- Timestamps are parsed day-first (the file uses d/m/Y). Pandas guesses month-first by default, which wrongly gave April 7 instead of July 4.
- inf values are replaced with NaN. Rows with NaN are kept, because dropping could delete attack rows silently. NaN handling is deferred to the modelling step.
- Duplicates Decision: KEEP.
