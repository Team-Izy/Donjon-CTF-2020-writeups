#!/usr/bin/env python
from random import randint
from Crypto.Hash import SHA256

INIT_VALUES = [
    11, 19, 43, 19, 53, 31, 53,
    5,  43, 13, 13, 53, 23, 23,
    37, 37, 37, 13, 31, 23, 11
]

GRID_CONTRAINTS = [
    [56, 36, 19, 17, 28, 30, 64, 15, 22],
    [53, 69, 46, 55, 54, 74,  7, 45, 26],
    [52, 70, 11, 47,  8,  9, 16, 76, 78],
    [35, 49, 18, 70,  8, 76, 44, 28, 32],
    [31,  5, 68, 25, 32, 75,  2, 77, 29],
    [61, 37,  6, 10, 23, 39, 48, 36, 5 ],
    [40, 48, 14, 33, 44, 80, 65,  3, 13],
    [12, 61, 43, 50, 37, 20, 73,  6, 79],
    [72,  1, 67, 52, 47, 16, 33, 17, 25],
    [33, 44, 80, 17, 28, 30, 25, 32, 75],
    [72, 35, 63,  1, 49, 51, 67, 18, 60],
    [69, 54, 45, 41, 38,  0,  3, 15, 77],
    [12, 61, 43, 72, 35, 63, 53, 69, 46],
    [71, 23, 62, 47,  8,  9,  4, 38, 27],
    [57, 10, 66, 71, 23, 62, 34, 39, 58],
    [73,  6, 79, 67, 18, 60,  7, 45, 26],
    [34, 39, 58, 16, 76, 78, 59,  0, 21],
    [46, 74, 26, 42, 27, 21, 13, 22, 29],
    [65,  3, 13, 64, 15, 22,  2, 77, 29],
    [43, 20, 79, 66, 62, 58, 14, 19, 68],
    [40, 48, 14, 56, 36, 19, 31,  5, 68],
    [50, 37, 20,  1, 49, 51, 55, 54, 74],
    [24, 41, 42,  4, 38, 27, 59,  0, 21],
    [63, 51, 60, 11,  9, 78, 80, 30, 75],
    [53, 55,  7, 24,  4, 59, 65, 64, 2 ],
    [57, 10, 66, 52, 70, 11, 24, 41, 42],
    [12, 50, 73, 57, 71, 34, 40, 56, 31]
]

def to_primes(x):
    return [0, 5, 11, 13, 19, 23, 31, 37, 43, 53][x]

def to_int(x):
    return {5: 1, 11: 2, 13: 3, 19: 4, 23: 5, 31: 6, 37: 7, 43: 8, 53: 9}[x]

def build_grid_from_contraints(grid):
    """
    Try to construct a sudoku grid which is match the constraints.

    Note: The function will very unlikely returns the original grid,
    however, the returned grid is isomorph to the original grid so 
    the solution is equivalent.
    """
    grid = [ set(e) for e in grid ]

    #
    # Step 1: find squares inside using the constraints.
    #
    # To find the regions, we compare each constraints set with all
    # the others:
    # - if we compare two rows (or colums, regions): the intersection
    #   is always void.
    # - if we compare a row with a column: the intersection is compose
    #   of one element.
    # - if we compare a row (or column) with a regions: the intersection
    #   is either void or contains three elements.
    #
    # Hence, the regions constraints are the ones that have an empty
    # intersection or an intersection containing three elements.
    #
    # Note: Regions are the 3x3 boxes that compose the grid.
    #
    regions, others = [], []
    for i in range(27):
        is_region = True
        for j in range(27):
            if i == j:
                continue
            if len(grid[i].intersection(grid[j])) == 1:
                is_region  = False
                break
        if is_region:
            regions.append(grid[i])
        else:
            others.append(grid[i])

    #
    # Step 2: using the same method as above, we now split the remaining constraints
    # in two sets: columns and rows.
    #
    grid = others
    rows, columns = [], []
    rows_set = set()
    for i in range(18):
        if len(rows_set.intersection(grid[i])) == 0:
            rows.append(grid[i])
            rows_set |= grid[i]
        else:
            columns.append(grid[i])

    # Quick sanity check
    assert len(regions) == len(rows) == len(columns) == 9

    #
    # Step 3: build a dict contaning the links between the regions.
    #
    # We consider that regions and rows/columns are linked when they
    # share cells.
    #
    region_links = {}
    for i, region in enumerate(regions):
        region_links[i] = { "col" : set() , "row": set() }
        for j, row in enumerate(rows):
            l = len(region.intersection(row))
            if l == 3:
                region_links[i]["row"].add(j)
            elif l == 0:
                continue
            else:
                raise NotPossibleMamene

        for j, column in enumerate(columns):
            l = len(region.intersection(column))
            if l == 3:
                region_links[i]["col"].add(j)
            elif l == 0:
                continue
            else:
                raise NotPossibleMamene

        assert len(region_links[i]["col"]) == 3
        assert len(region_links[i]["row"]) == 3

    #
    # Step 4: we arrange the regions inside the final sudoku grid.
    #
    # To arrange the regions we ensure that regions on the same
    # row (resp. column) share the same rows (resp. columns) constraints.
    #
    # Here we can already notice that it exists multiple solutions (3! * 3!) an
    # we arbitrary choose one.
    #
    region_matrix = [[-1]*3, [-1]*3, [-1]*3]
    indexes_used = set()

    i = 0
    while i < 3:
        j = 0
        idx = 0
        row_const_ref = None
        while idx < 9:

            # If this index has already been used skip it
            if idx in indexes_used:
                idx += 1
                continue

            if not row_const_ref:

                # This should not happen for column != 0
                assert j == 0

                if i == 0:
                    indexes_used.add(idx)
                    row_const_ref = region_links[idx]["row"]
                    region_matrix[i][j] = idx
                    j += 1
                    idx = 0
                else:
                    col_const_ref = region_links[region_matrix[i-1][j]]["col"]
                    col_const_cur = region_links[idx]["col"]
                    if len(col_const_ref.intersection(col_const_cur)) == 3:
                        indexes_used.add(idx)
                        row_const_ref = region_links[idx]["row"]
                        region_matrix[i][j] = idx
                        idx = 0
                        j += 1
            else:
                row_const_cur = region_links[idx]["row"]
                if len(row_const_ref.intersection(row_const_cur)) == 3:
                    if i == 0:
                        indexes_used.add(idx)
                        row_const_ref = region_links[idx]["row"]
                        region_matrix[i][j] = idx
                        j += 1
                        idx = 0
                    else:
                        col_const_ref = region_links[region_matrix[i-1][j]]["col"]
                        col_const_cur = region_links[idx]["col"]
                        if len(col_const_ref.intersection(col_const_cur)) == 3:
                            indexes_used.add(idx)
                            row_const_ref = region_links[idx]["row"]
                            region_matrix[i][j] = idx
                            j += 1
                            idx = 0
            idx += 1

        # All the column should be filled now
        assert j == 3
        i += 1

    #
    # Step 5: populate the sudoku constraints matrix with the constraints
    # on the regions.
    #
    # Constraints: [square, line, column]
    #
    sudoku_constraints = [ [[-1, -1, -1] for _ in range(9)] for _ in range(9) ]
    for i in range(9):
        for j in range(9):
            sudoku_constraints[i][j][0] = region_matrix[i // 3][j // 3]

    #
    # Step 6: finally fill the sudoku cells using the constraints
    # previously set. If we do not have any constraints on the row/column
    # we arbitrary one that match the region constraints.
    #
    sudoku_grid = [ [0] * 9 for _ in range(9) ]
    lines_used   = set()
    columns_used = set()
    for i in range(9):
        for j in range(9):

            constraints = sudoku_constraints[i][j]
            square_idx = constraints[0]

            # Check if we have any constraints on the row / column
            if constraints[1] == -1 and constraints[2] == -1:

                chosen_line_idx = -1
                for line_idx in region_links[square_idx]["row"]:
                    if not line_idx in lines_used:
                        chosen_line_idx = line_idx
                        break

                chosen_column_idx = -1
                for column_idx in region_links[square_idx]["col"]:
                    if not column_idx in columns_used:
                        chosen_column_idx = column_idx
                        break

                if chosen_line_idx == -1 or chosen_column_idx == -1:
                    raise MegaError

                lines_used.add(chosen_line_idx)
                columns_used.add(chosen_column_idx)

                # Replicate the new constraints
                for k in range(9):
                    sudoku_constraints[i][k][1] = chosen_line_idx
                    sudoku_constraints[k][j][2] = chosen_column_idx

            elif constraints[1] == -1:

                chosen_line_idx = -1
                for line_idx in region_links[square_idx]["row"]:
                    if not line_idx in lines_used:
                        chosen_line_idx = line_idx
                        break

                if chosen_line_idx == -1:
                    raise MegaError

                lines_used.add(chosen_line_idx)

                # Replicate the new constraints
                for k in range(9):
                    sudoku_constraints[i][k][1] = chosen_line_idx

            elif constraints[2] == -1:

                chosen_column_idx = -1
                for column_idx in region_links[square_idx]["col"]:
                    if not column_idx in columns_used:
                        chosen_column_idx = column_idx
                        break

                if chosen_column_idx == -1:
                    raise MegaError

                columns_used.add(chosen_column_idx)

                # Replicate the new constraints
                for k in range(9):
                    sudoku_constraints[k][j][2] = chosen_column_idx

            # Normally we should have enough constraints to fill the case
            c1 = regions[constraints[0]]
            c2 = rows[constraints[1]]
            c3 = columns[constraints[2]]

            c = c1.intersection(c2).intersection(c3)

            # The intersection should only contains one element
            assert len(c) == 1

            sudoku_grid[i][j] = c.pop()

    # print("final sudoku_grid:", sudoku_grid)
    return sudoku_grid

def draw_grid(sudoku_grid, init_values):
    """
    Draw the sudoku grid
    """
    for i in range(9):
        s = ""
        for j in range(9):
            k = sudoku_grid[i][j]
            if k in init_values:
                s += str(init_values[k])
            else:
                s += "x"
            s += " "
        print(s)

def get_init_values():
    """
    Construct a dict containing the init values
    """
    init_values = {}
    for i in range(len(INIT_VALUES)):
        v = INIT_VALUES[i]
        init_values[i] = to_int(v)

    return init_values

def print_flag(sudoku_grid, solution):
    """
    Get the flag from the solution and the sudoku grid
    """
    d = {}
    for i in range(9):
        for j in range(9):
            d[sudoku_grid[i][j]] = to_primes(solution[i][j])

    ans = b""
    for i in range(81):
        ans += bytes([d[i]])

    sha256_hash = bytearray(SHA256.new(ans).digest())[:26]

    XOR_ARRAY = [
        0xC9, 0x66, 0x4B, 0x7A, 0x20, 0x34, 0xE3, 0x99, 0x36, 0x23,
        0x42, 0x28, 0x1F, 0xE2, 0x7C, 0x5C, 0xCC, 0x5C, 0xF2, 0x95,
        0x52, 0x18, 0xDF, 0xE8, 0x92, 0x93
    ]

    for i in range(26):
        sha256_hash[i] ^= XOR_ARRAY[i]

    flag = sha256_hash.decode("utf-8")

    print(f"[+] Flag: {flag}")

def main():
    """
    Main function
    """

    # Try to construct a sudoku grid which satisfies
    # the constraints
    real_grid = build_grid_from_contraints(GRID_CONTRAINTS)

    # Draw the sudoku grid so we can play with
    draw_grid(real_grid, get_init_values())

    # Hardcoded solution
    solution = [
        [8, 6, 4, 5, 7, 1, 3, 9, 2],
        [5, 2, 1, 4, 9, 3, 6, 8, 7],
        [9, 3, 7, 6, 8, 2, 5, 4, 1],
        [7, 9, 6, 8, 2, 5, 1, 3, 4],
        [3, 1, 8, 9, 6, 4, 7, 2, 5],
        [4, 5, 2, 3, 1, 7, 9, 6, 8],
        [6, 4, 5, 7, 3, 8, 2, 1, 9],
        [1, 7, 9, 2, 4, 6, 8, 5, 3],
        [2, 8, 3, 1, 5, 9, 4, 7, 6]
    ]

    # Display the flag
    print_flag(real_grid, solution)

if __name__ == "__main__":
    main()
