---
layout: post
title: Generators in Python
date: 2025-04-23 13:45 +0300
categories: [Programming, Python]
tags: [generators, return, yield, performance, efficiency]
---

## 1. What Are Generators?

Generators are special functions in Python that allow you to declare a function that behaves like an iterator. They enable you to iterate over a potentially large sequence of data without loading the entire sequence into memory at once.

Key characteristics:
- Created using functions with the `yield` statement
- Execute lazily (on-demand)
- Maintain their state between calls
- Can represent infinite sequences
- Are memory efficient

## 2. Creating Generators

### Function-Based Generators

```python
def count_up_to(max):
    count = 1
    while count <= max:
        yield count
        count += 1
```

### Generator Expressions (Similar to List Comprehensions)

```python
# List comprehension (creates entire list in memory)
squares_list = [x**2 for x in range(1000)]

# Generator expression (creates values on-demand)
squares_gen = (x**2 for x in range(1000))
```

## 3. The `next()` Function

The `next()` function is used to request the next item from a generator:

```python
gen = count_up_to(5)
print(next(gen))  # 1
print(next(gen))  # 2
print(next(gen))  # 3
```

### Key Behavior of `next()`

- When called on a generator, it resumes execution until the next `yield` statement
- Returns the value provided to `yield`
- When no more values are available, raises `StopIteration` exception
- Can receive a default value: `next(gen, default_value)`

### Example with Exception Handling

```python
gen = count_up_to(2)
print(next(gen))  # 1
print(next(gen))  # 2
try:
    print(next(gen))  # Will raise StopIteration
except StopIteration:
    print("Generator exhausted")
```

## 4. How Generators Work

### Execution Flow

1. When you call a generator function, it returns a generator object without executing the function body
2. Each call to `next()` executes code until it reaches a `yield` statement
3. The generator's state (local variables, execution position) is saved
4. Execution resumes from the saved state on the next call to `next()`

### Generator States

- **GEN_CREATED**: Initial state after creation, before first execution
- **GEN_RUNNING**: Currently executing
- **GEN_SUSPENDED**: Paused at a `yield` statement
- **GEN_CLOSED**: Completed or closed

## 5. Advantages of Generators

### Memory Efficiency

- Only generate values when needed, rather than storing all values in memory
- Ideal for large datasets or streams
- Example: Reading large files

```python
def read_large_file(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            yield line.strip()
```

### Infinite Sequences

- Can represent theoretically infinite sequences
- Computation happens only for requested values

```python
def infinite_sequence():
    num = 0
    while True:
        yield num
        num += 1
```

### Code Simplicity and Readability

- Make complex iteration patterns simple to express
- Maintain clean separation between iteration logic and processing logic

### Performance Benefits

- Reduce latency for first results (don't need to compute entire sequence)
- Eliminate unnecessary computations if only part of sequence is needed
- Can save both CPU and memory resources

## 6. Advanced Generator Features

### Sending Values to Generators (`send()` method)

```python
def echo_generator():
    value = yield
    while True:
        value = yield f"Echo: {value}"

gen = echo_generator()
next(gen)  # Prime the generator
print(gen.send("Hello"))  # Echo: Hello
```

### Generator Delegation (`yield from`)

```python
def generator1():
    yield from range(3)
    yield from range(4, 6)

for item in generator1():
    print(item)  # 0, 1, 2, 4, 5
```

### Closing Generators (`close()` method)

```python
def closeable_generator():
    try:
        yield 1
        yield 2
        yield 3
    finally:
        print("Generator closed!")

gen = closeable_generator()
print(next(gen))  # 1
gen.close()  # "Generator closed!" is printed
```

## 7. Common Use Cases

### Data Processing Pipelines

```python
def read_data(file_path):
    with open(file_path) as f:
        for line in f:
            yield line.strip()

def parse_data(lines):
    for line in lines:
        yield line.split(',')

def filter_data(records):
    for record in records:
        if len(record) >= 3 and record[2].isdigit():
            yield record

# Usage
data = read_data('data.csv')
parsed_data = parse_data(data)
filtered_data = filter_data(parsed_data)
```

### Database Record Processing

```python
def process_records(cursor):
    for record in cursor.fetchmany(size=100):
        yield process_record(record)
```

### Mathematical Sequences

```python
def fibonacci():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b
```

## 8. Best Practices

### When to Use Generators

- Working with large datasets
- Processing streams of data
- Creating data pipelines
- Representing potentially infinite sequences
- Improving memory usage

### When Not to Use Generators

- When you need random access to elements
- When you need to use the sequence multiple times
- When you need to know the length in advance

### Generator Performance Tips

- Use generator expressions for simple cases
- Consider caching results if the same values will be needed repeatedly
- Be aware that generators are consumed when iterated (can't reuse without recreating)

## 9. Generators vs. Iterators

Generators are a subset of iterators with a more concise syntax:

| Feature | Iterators | Generators |
|---------|-----------|------------|
| Creation | Implement `__iter__()` and `__next__()` | Use `yield` statement |
| State Management | Manual (instance variables) | Automatic |
| Complexity | More boilerplate code | Concise |
| Memory Usage | Depends on implementation | Typically efficient |

## 10. Real-World Examples

### Web Scraping

```python
def scrape_pages(base_url, max_pages):
    for i in range(1, max_pages + 1):
        response = requests.get(f"{base_url}/page/{i}")
        yield response.text
```

### Custom Range Function

```python
def frange(start, stop, step):
    current = start
    while current < stop:
        yield current
        current += step

for num in frange(0, 1, 0.1):
    print(round(num, 1), end=', ')  # 0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9
```

### Data Transformation

```python
def normalize_data(data_points):
    total = sum(data_points)
    for point in data_points:
        yield point / total
```

