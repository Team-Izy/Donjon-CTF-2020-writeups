from sage.all import GF, EllipticCurve
from ecpy.curves     import Curve,Point
cv     = Curve.get_curve('secp256k1')
pub = Point(94443785317487831642935972645202783659685599642218408192269455854005741686810,
            78142542704322095768523419012865788964201745299563420996262654666896320550926,cv)
p = cv.field


"""
Delete Zdel from level k, and its parent if it has no other child than the oe we just deleted
"""
def backdelete(k, Z_R_K, Zdel):
    if k == 0:
        assert False
    #search and remove Zdel from level k
    i = 0
    while i < len(Z_R_K[k]):
        Zi, _, _, Zim1 = Z_R_K[k][i]
        if Zi == Zdel:
            #print(f"Deleting {Z_R_K[k][i]}")
            del Z_R_K[k][i]
            break
        i += 1
    else:
        assert False
    #if nobody has the same parent in level k, the parent is also wrong
    i = 0
    while i < len(Z_R_K[k]):
        _, _, _, Zim1_other = Z_R_K[k][i]
        if Zim1_other == Zim1:
            break
        i += 1
    else:
        backdelete(k-1, Z_R_K, Zim1)


with open("./Z_and_points.dict", "r") as f:
    Z_and_points = eval(f.read())

G = cv.generator
Gx = G.x
n = cv.order
print(f"G : {hex(G.x)}, {hex(G.y)}")
print(f"p={hex(p), {p}}")
print(f"n={hex(n), {n}}")

Fp = GF(p)
inv_2_mod_n = pow(2, -1, n)

f = open("./recovered_kbits.txt", "w")

for (j,d) in enumerate(Z_and_points):
    Z0, R0, h, r, s = d["Z"], d["P"], d["h"], d["r"], d["s"]
    R0 = Point(R0[0], R0[1], cv)
    Z0 = Fp(Z0)
    k_bits = list()
    Z_R_K = [[(Z0, R0, tuple(), None)]] #for each depth i, contains the list of possible combinations of (Z_i, R_i, [k_j for j in range(i)[::-1]], Z_{i-1})

    for i in range(10):
        Z_R_K.append(list())
        Z_R_K_i = list(Z_R_K[i])
        for Zi, Ri, k_bits, Zim1 in Z_R_K_i:
            # case where k_i = 0
            R_ip1_if_double = inv_2_mod_n * Ri # R_{i+1} = R_i  / 2
            yi = Fp(R_ip1_if_double.y)
            Zi_2yi = Zi / (Fp(2) * yi)
            quad_roots = Zi_2yi.nth_root(4, all=True)
            Z_ip1_for_ki_equals_0 = quad_roots # solutions for Z_{i+1} if k_i = 0

            # case where k_i = 1
            T_i_if_add = Ri - G # T_i = R_i - G
            R_ip1_if_add = inv_2_mod_n * T_i_if_add # R_{i+1} = T_i  / 2
            yi = Fp(R_ip1_if_add.y)
            Zi_2xgxt = Zi / (Fp(2)*(Fp(Gx)-Fp(T_i_if_add.x)))
            cube_roots = Zi_2xgxt.nth_root(3, all=True)
            Z_ip1_for_ki_equals_1 = list()
            for Z_Tip1 in cube_roots:
                Z_Tip1_2yi = Z_Tip1 / (Fp(2) * yi)
                quad_roots = Z_Tip1_2yi.nth_root(4, all=True)
                Z_ip1_for_ki_equals_1.extend(quad_roots) # solutions for Z_{i+1} if k_i = 1

            # if both case bear no solution, the explored solution was already impossible
            if not(len(Z_ip1_for_ki_equals_0) or len(Z_ip1_for_ki_equals_1)):
                backdelete(i, Z_R_K, Zi)

            for Z_ip1 in Z_ip1_for_ki_equals_0:
                Z_R_K[i+1].append((Z_ip1, R_ip1_if_double, tuple([0] + list(k_bits)), Zi))
            for Z_ip1 in Z_ip1_for_ki_equals_1:
                Z_R_K[i+1].append((Z_ip1, R_ip1_if_add,    tuple([1] + list(k_bits)), Zi))

            if len(Z_R_K[i+1]) > 8: # stop exploration if the number of solutions for a certain depth is too big (arbitrary)
                break
        else:
            continue
        break

    k_bits_len = [len(set(l[2] for l in e)) for e in Z_R_K]
    nb_k_bits_recovered = k_bits_len.count(1)-1
    print(j, k_bits_len, nb_k_bits_recovered, Z_R_K[nb_k_bits_recovered][0][2])
    f.write(repr(Z_R_K[nb_k_bits_recovered][0][2]))
    f.write("\n")

f.close()
