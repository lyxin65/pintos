#ifndef FIXED_POINT_H
#define FIXED_POINT_H

static const int p = 17;
static const int q = 14;
static const int f = 1 << 14;

int itofp(int n);
int fptoi0(int x);
int fptoi(int x);
int fp_add(int x, int y);
int fp_sub(int x, int y);
int fp_add_int(int x, int n);
int fp_sub_int(int x, int n);
int fp_mul(int x, int y);
int fp_mul_int(int x, int n);
int fp_div(int x, int y);
int fp_div_int(int x, int n);

int itofp(int n) {
    return n * f;
}

int fptoi0(int x) {
    return x / f;
}

int fptoi(int x) {
    if (x >= 0) {
        return (x + f/2) / f;
    } else {
        return (x - f/2) / f;
    }
}

int fp_add(int x, int y) {
    return x + y;
}

int fp_sub(int x, int y) {
    return x - y;
}

int fp_add_int(int x, int n) {
    return x + n * f;
}

int fp_sub_int(int x, int n) {
    return x - n * f;
}

int fp_mul(int x, int y) {
    return ((int64_t) x) * y / f;
}

int fp_mul_int(int x, int n) {
    return x * n;
}

int fp_div(int x, int y) {
    return ((int64_t) x) * f / y;
}

int fp_div_int(int x, int n) {
    return x / n;
}


#endif // FIXED_POINT_H
