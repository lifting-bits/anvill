; ModuleID = 'chall2.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

%sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0 = type <{ [368 x i8] }>

@var_402020__Cbx26_D = external global [26 x i8]
@var_40203a__Cbx19_D = external global [19 x i8]
@var_40204d__Cbx1_D = external global [1 x i8]
@var_40204f__Cbx1_D = external global [1 x i8]
@var_402057__Cbx9_D = external global [9 x i8]
@var_402060__Cbx56_D = external global [56 x i8]
@var_40209c__Cbx21_D = external global [21 x i8]
@var_4020b5__Cbx15_D = external global [15 x i8]
@var_4020c4__Cbx24_D = external global [24 x i8]
@__anvill_reg_RBX = internal local_unnamed_addr global i64 0
@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_reg_R12 = internal local_unnamed_addr global i64 0
@__anvill_reg_R13 = internal local_unnamed_addr global i64 0
@__anvill_reg_R14 = internal local_unnamed_addr global i64 0
@__anvill_reg_R15 = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [64 x ptr] [ptr @sub_401030__A_Sb_Sb_Sb_B_0, ptr @sub_401040__A_Sbi_B_0, ptr @sub_401050__Aiii_Sbii_B_0, ptr @sub_401060__Ai_Sbll_B_0, ptr @sub_401070__Avl_B_0, ptr @sub_401080__A_Sl_Sb_B_0, ptr @sub_401090__A_Sb_Vi_B_0, ptr @sub_4010a0__A_Sbl_Sb_Vi_B_0, ptr @sub_4010b0__Ailil_B_0, ptr @sub_4010c0__Ail_Vi_B_0, ptr @sub_4010d0__Ai_Sbll_B_0, ptr @sub_4010e0__A_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_Sb_Vi_B_0, ptr @sub_4010f0__A_Sll_B_0, ptr @sub_401100__Ai_S_X0_E_Clx16_D_F_S_X1_E_Clx16_D_F_S_X2_E_Clx16_D_F_S_X3_Ell_Fi_B_0, ptr @sub_401110__All_B_0, ptr @sub_401120__Ai_S_X0_Eh_Cbx14_D_Fii_B_0, ptr @sub_401130__A_Sbi_Vi_B_0, ptr @sub_401140__A_Sb_Sb_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_B_0, ptr @sub_401150__A_Sbv_B_0, ptr @sub_401160__Aii_B_0, ptr @sub_401170__Aiiii_B_0, ptr @sub_4011a4__All_Svl_B_0, ptr @sub_401270__Ai_S_Sb_S_Sbi_B_0, ptr @sub_401610__A_Si_Sbl_B_0, ptr @sub_401690__A_Sb_Sbl_B_0, ptr @sub_4016d0__A_Sb_Sbl_B_0, ptr @sub_4016e0__Avl_B_0, ptr @sub_401920__Aiil_B_0, ptr @sub_401a70__Ailil_B_0, ptr @sub_401af0__Aiil_B_0, ptr @sub_401b80__A_Sll_B_0, ptr @sub_401c60__A_Sbl_B_0, ptr @sub_401cd0__A_Sbv_B_0, ptr @sub_404138__A_Svi_S_Sb_Sv_Sv_Sv_Sbi_B_78, ptr @sub_404140__Ai_S_X0_Eh_Cbx14_D_Fii_B_78, ptr @sub_404148__Avl_B_78, ptr @sub_404150__A_Sl_Sb_B_78, ptr @sub_404158__A_Sb_Sb_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_B_78, ptr @sub_404160__A_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_Sb_Vi_B_78, ptr @sub_404168__Ail_Vi_B_78, ptr @sub_404170__Ailil_B_78, ptr @sub_404178__Al_Sb_B_78, ptr @sub_404180__A_Sbi_Vi_B_78, ptr @sub_404188__A_Sbv_B_78, ptr @sub_404190__A_Sb_Vi_B_78, ptr @sub_404198__A_Sbi_B_78, ptr @sub_4041a0__Ai_Sbll_B_78, ptr @sub_4041a8__Ai_S_X0_E_Clx16_D_F_S_M0_S_M0_S_X1_Ell_Fi_B_78, ptr @sub_4041b0__Aiii_Sbii_B_78, ptr @sub_4041b8__Aii_B_78, ptr @sub_4041c0__A_Sbl_Sb_Vi_B_78, ptr @sub_4041c8__Aiiii_B_78, ptr @sub_4041d0__A_Sb_Sb_Sb_B_78, ptr @sub_4041d8__A_Sll_B_78, ptr @sub_4041e0__Ai_Sbll_B_78, ptr getelementptr inbounds ([26 x i8], ptr @var_402020__Cbx26_D, i32 0, i32 0), ptr getelementptr inbounds ([19 x i8], ptr @var_40203a__Cbx19_D, i32 0, i32 0), ptr getelementptr inbounds ([1 x i8], ptr @var_40204d__Cbx1_D, i32 0, i32 0), ptr getelementptr inbounds ([1 x i8], ptr @var_40204f__Cbx1_D, i32 0, i32 0), ptr getelementptr inbounds ([9 x i8], ptr @var_402057__Cbx9_D, i32 0, i32 0), ptr getelementptr inbounds ([56 x i8], ptr @var_402060__Cbx56_D, i32 0, i32 0), ptr getelementptr inbounds ([21 x i8], ptr @var_40209c__Cbx21_D, i32 0, i32 0), ptr getelementptr inbounds ([15 x i8], ptr @var_4020b5__Cbx15_D, i32 0, i32 0), ptr getelementptr inbounds ([24 x i8], ptr @var_4020c4__Cbx24_D, i32 0, i32 0)], section "llvm.metadata"
@__anvill_stack_minus_368 = global i8 0
@__anvill_stack_minus_367 = global i8 0
@__anvill_stack_minus_366 = global i8 0
@__anvill_stack_minus_365 = global i8 0
@__anvill_stack_minus_364 = global i8 0
@__anvill_stack_minus_363 = global i8 0
@__anvill_stack_minus_362 = global i8 0
@__anvill_stack_minus_361 = global i8 0
@__anvill_stack_minus_360 = global i8 0
@__anvill_stack_minus_359 = global i8 0
@__anvill_stack_minus_358 = global i8 0
@__anvill_stack_minus_357 = global i8 0
@__anvill_stack_minus_356 = global i8 0
@__anvill_stack_minus_355 = global i8 0
@__anvill_stack_minus_354 = global i8 0
@__anvill_stack_minus_353 = global i8 0
@__anvill_stack_minus_352 = global i8 0
@__anvill_stack_minus_351 = global i8 0
@__anvill_stack_minus_350 = global i8 0
@__anvill_stack_minus_349 = global i8 0
@__anvill_stack_minus_348 = global i8 0
@__anvill_stack_minus_347 = global i8 0
@__anvill_stack_minus_346 = global i8 0
@__anvill_stack_minus_345 = global i8 0
@__anvill_stack_minus_344 = global i8 0
@__anvill_stack_minus_343 = global i8 0
@__anvill_stack_minus_342 = global i8 0
@__anvill_stack_minus_341 = global i8 0
@__anvill_stack_minus_340 = global i8 0
@__anvill_stack_minus_339 = global i8 0
@__anvill_stack_minus_338 = global i8 0
@__anvill_stack_minus_337 = global i8 0
@__anvill_stack_minus_336 = global i8 0
@__anvill_stack_minus_335 = global i8 0
@__anvill_stack_minus_334 = global i8 0
@__anvill_stack_minus_333 = global i8 0
@__anvill_stack_minus_332 = global i8 0
@__anvill_stack_minus_331 = global i8 0
@__anvill_stack_minus_330 = global i8 0
@__anvill_stack_minus_329 = global i8 0
@__anvill_stack_minus_328 = global i8 0
@__anvill_stack_minus_327 = global i8 0
@__anvill_stack_minus_326 = global i8 0
@__anvill_stack_minus_325 = global i8 0
@__anvill_stack_minus_324 = global i8 0
@__anvill_stack_minus_323 = global i8 0
@__anvill_stack_minus_322 = global i8 0
@__anvill_stack_minus_321 = global i8 0
@__anvill_stack_minus_320 = global i8 0
@__anvill_stack_minus_319 = global i8 0
@__anvill_stack_minus_318 = global i8 0
@__anvill_stack_minus_317 = global i8 0
@__anvill_stack_minus_316 = global i8 0
@__anvill_stack_minus_315 = global i8 0
@__anvill_stack_minus_314 = global i8 0
@__anvill_stack_minus_313 = global i8 0
@__anvill_stack_minus_312 = global i8 0
@__anvill_stack_minus_311 = global i8 0
@__anvill_stack_minus_310 = global i8 0
@__anvill_stack_minus_309 = global i8 0
@__anvill_stack_minus_308 = global i8 0
@__anvill_stack_minus_307 = global i8 0
@__anvill_stack_minus_306 = global i8 0
@__anvill_stack_minus_305 = global i8 0
@__anvill_stack_minus_304 = global i8 0
@__anvill_stack_minus_303 = global i8 0
@__anvill_stack_minus_302 = global i8 0
@__anvill_stack_minus_301 = global i8 0
@__anvill_stack_minus_300 = global i8 0
@__anvill_stack_minus_299 = global i8 0
@__anvill_stack_minus_298 = global i8 0
@__anvill_stack_minus_297 = global i8 0
@__anvill_stack_minus_296 = global i8 0
@__anvill_stack_minus_295 = global i8 0
@__anvill_stack_minus_294 = global i8 0
@__anvill_stack_minus_293 = global i8 0
@__anvill_stack_minus_292 = global i8 0
@__anvill_stack_minus_291 = global i8 0
@__anvill_stack_minus_290 = global i8 0
@__anvill_stack_minus_289 = global i8 0
@__anvill_stack_minus_288 = global i8 0
@__anvill_stack_minus_287 = global i8 0
@__anvill_stack_minus_286 = global i8 0
@__anvill_stack_minus_285 = global i8 0
@__anvill_stack_minus_284 = global i8 0
@__anvill_stack_minus_283 = global i8 0
@__anvill_stack_minus_282 = global i8 0
@__anvill_stack_minus_281 = global i8 0
@__anvill_stack_minus_280 = global i8 0
@__anvill_stack_minus_279 = global i8 0
@__anvill_stack_minus_278 = global i8 0
@__anvill_stack_minus_277 = global i8 0
@__anvill_stack_minus_276 = global i8 0
@__anvill_stack_minus_275 = global i8 0
@__anvill_stack_minus_274 = global i8 0
@__anvill_stack_minus_273 = global i8 0
@__anvill_stack_minus_272 = global i8 0
@__anvill_stack_minus_271 = global i8 0
@__anvill_stack_minus_270 = global i8 0
@__anvill_stack_minus_269 = global i8 0
@__anvill_stack_minus_268 = global i8 0
@__anvill_stack_minus_267 = global i8 0
@__anvill_stack_minus_266 = global i8 0
@__anvill_stack_minus_265 = global i8 0
@__anvill_stack_minus_264 = global i8 0
@__anvill_stack_minus_263 = global i8 0
@__anvill_stack_minus_262 = global i8 0
@__anvill_stack_minus_261 = global i8 0
@__anvill_stack_minus_260 = global i8 0
@__anvill_stack_minus_259 = global i8 0
@__anvill_stack_minus_258 = global i8 0
@__anvill_stack_minus_257 = global i8 0
@__anvill_stack_minus_256 = global i8 0
@__anvill_stack_minus_255 = global i8 0
@__anvill_stack_minus_254 = global i8 0
@__anvill_stack_minus_253 = global i8 0
@__anvill_stack_minus_252 = global i8 0
@__anvill_stack_minus_251 = global i8 0
@__anvill_stack_minus_250 = global i8 0
@__anvill_stack_minus_249 = global i8 0
@__anvill_stack_minus_248 = global i8 0
@__anvill_stack_minus_247 = global i8 0
@__anvill_stack_minus_246 = global i8 0
@__anvill_stack_minus_245 = global i8 0
@__anvill_stack_minus_244 = global i8 0
@__anvill_stack_minus_243 = global i8 0
@__anvill_stack_minus_242 = global i8 0
@__anvill_stack_minus_241 = global i8 0
@__anvill_stack_minus_240 = global i8 0
@__anvill_stack_minus_239 = global i8 0
@__anvill_stack_minus_238 = global i8 0
@__anvill_stack_minus_237 = global i8 0
@__anvill_stack_minus_236 = global i8 0
@__anvill_stack_minus_235 = global i8 0
@__anvill_stack_minus_234 = global i8 0
@__anvill_stack_minus_233 = global i8 0
@__anvill_stack_minus_232 = global i8 0
@__anvill_stack_minus_231 = global i8 0
@__anvill_stack_minus_230 = global i8 0
@__anvill_stack_minus_229 = global i8 0
@__anvill_stack_minus_228 = global i8 0
@__anvill_stack_minus_227 = global i8 0
@__anvill_stack_minus_226 = global i8 0
@__anvill_stack_minus_225 = global i8 0
@__anvill_stack_minus_224 = global i8 0
@__anvill_stack_minus_223 = global i8 0
@__anvill_stack_minus_222 = global i8 0
@__anvill_stack_minus_221 = global i8 0
@__anvill_stack_minus_220 = global i8 0
@__anvill_stack_minus_219 = global i8 0
@__anvill_stack_minus_218 = global i8 0
@__anvill_stack_minus_217 = global i8 0
@__anvill_stack_minus_216 = global i8 0
@__anvill_stack_minus_215 = global i8 0
@__anvill_stack_minus_214 = global i8 0
@__anvill_stack_minus_213 = global i8 0
@__anvill_stack_minus_212 = global i8 0
@__anvill_stack_minus_211 = global i8 0
@__anvill_stack_minus_210 = global i8 0
@__anvill_stack_minus_209 = global i8 0
@__anvill_stack_minus_208 = global i8 0
@__anvill_stack_minus_207 = global i8 0
@__anvill_stack_minus_206 = global i8 0
@__anvill_stack_minus_205 = global i8 0
@__anvill_stack_minus_204 = global i8 0
@__anvill_stack_minus_203 = global i8 0
@__anvill_stack_minus_202 = global i8 0
@__anvill_stack_minus_201 = global i8 0
@__anvill_stack_minus_200 = global i8 0
@__anvill_stack_minus_199 = global i8 0
@__anvill_stack_minus_198 = global i8 0
@__anvill_stack_minus_197 = global i8 0
@__anvill_stack_minus_196 = global i8 0
@__anvill_stack_minus_195 = global i8 0
@__anvill_stack_minus_194 = global i8 0
@__anvill_stack_minus_193 = global i8 0
@__anvill_stack_minus_192 = global i8 0
@__anvill_stack_minus_191 = global i8 0
@__anvill_stack_minus_190 = global i8 0
@__anvill_stack_minus_189 = global i8 0
@__anvill_stack_minus_188 = global i8 0
@__anvill_stack_minus_187 = global i8 0
@__anvill_stack_minus_186 = global i8 0
@__anvill_stack_minus_185 = global i8 0
@__anvill_stack_minus_184 = global i8 0
@__anvill_stack_minus_183 = global i8 0
@__anvill_stack_minus_182 = global i8 0
@__anvill_stack_minus_181 = global i8 0
@__anvill_stack_minus_180 = global i8 0
@__anvill_stack_minus_179 = global i8 0
@__anvill_stack_minus_178 = global i8 0
@__anvill_stack_minus_177 = global i8 0
@__anvill_stack_minus_176 = global i8 0
@__anvill_stack_minus_175 = global i8 0
@__anvill_stack_minus_174 = global i8 0
@__anvill_stack_minus_173 = global i8 0
@__anvill_stack_minus_172 = global i8 0
@__anvill_stack_minus_171 = global i8 0
@__anvill_stack_minus_170 = global i8 0
@__anvill_stack_minus_169 = global i8 0
@__anvill_stack_minus_168 = global i8 0
@__anvill_stack_minus_167 = global i8 0
@__anvill_stack_minus_166 = global i8 0
@__anvill_stack_minus_165 = global i8 0
@__anvill_stack_minus_164 = global i8 0
@__anvill_stack_minus_163 = global i8 0
@__anvill_stack_minus_162 = global i8 0
@__anvill_stack_minus_161 = global i8 0
@__anvill_stack_minus_160 = global i8 0
@__anvill_stack_minus_159 = global i8 0
@__anvill_stack_minus_158 = global i8 0
@__anvill_stack_minus_157 = global i8 0
@__anvill_stack_minus_156 = global i8 0
@__anvill_stack_minus_155 = global i8 0
@__anvill_stack_minus_154 = global i8 0
@__anvill_stack_minus_153 = global i8 0
@__anvill_stack_minus_152 = global i8 0
@__anvill_stack_minus_151 = global i8 0
@__anvill_stack_minus_150 = global i8 0
@__anvill_stack_minus_149 = global i8 0
@__anvill_stack_minus_148 = global i8 0
@__anvill_stack_minus_147 = global i8 0
@__anvill_stack_minus_146 = global i8 0
@__anvill_stack_minus_145 = global i8 0
@__anvill_stack_minus_144 = global i8 0
@__anvill_stack_minus_143 = global i8 0
@__anvill_stack_minus_142 = global i8 0
@__anvill_stack_minus_141 = global i8 0
@__anvill_stack_minus_140 = global i8 0
@__anvill_stack_minus_139 = global i8 0
@__anvill_stack_minus_138 = global i8 0
@__anvill_stack_minus_137 = global i8 0
@__anvill_stack_minus_136 = global i8 0
@__anvill_stack_minus_135 = global i8 0
@__anvill_stack_minus_134 = global i8 0
@__anvill_stack_minus_133 = global i8 0
@__anvill_stack_minus_132 = global i8 0
@__anvill_stack_minus_131 = global i8 0
@__anvill_stack_minus_130 = global i8 0
@__anvill_stack_minus_129 = global i8 0
@__anvill_stack_minus_128 = global i8 0
@__anvill_stack_minus_127 = global i8 0
@__anvill_stack_minus_126 = global i8 0
@__anvill_stack_minus_125 = global i8 0
@__anvill_stack_minus_124 = global i8 0
@__anvill_stack_minus_123 = global i8 0
@__anvill_stack_minus_122 = global i8 0
@__anvill_stack_minus_121 = global i8 0
@__anvill_stack_minus_120 = global i8 0
@__anvill_stack_minus_119 = global i8 0
@__anvill_stack_minus_118 = global i8 0
@__anvill_stack_minus_117 = global i8 0
@__anvill_stack_minus_116 = global i8 0
@__anvill_stack_minus_115 = global i8 0
@__anvill_stack_minus_114 = global i8 0
@__anvill_stack_minus_113 = global i8 0
@__anvill_stack_minus_112 = global i8 0
@__anvill_stack_minus_111 = global i8 0
@__anvill_stack_minus_110 = global i8 0
@__anvill_stack_minus_109 = global i8 0
@__anvill_stack_minus_108 = global i8 0
@__anvill_stack_minus_107 = global i8 0
@__anvill_stack_minus_106 = global i8 0
@__anvill_stack_minus_105 = global i8 0
@__anvill_stack_minus_104 = global i8 0
@__anvill_stack_minus_103 = global i8 0
@__anvill_stack_minus_102 = global i8 0
@__anvill_stack_minus_101 = global i8 0
@__anvill_stack_minus_100 = global i8 0
@__anvill_stack_minus_99 = global i8 0
@__anvill_stack_minus_98 = global i8 0
@__anvill_stack_minus_97 = global i8 0
@__anvill_stack_minus_96 = global i8 0
@__anvill_stack_minus_95 = global i8 0
@__anvill_stack_minus_94 = global i8 0
@__anvill_stack_minus_93 = global i8 0
@__anvill_stack_minus_92 = global i8 0
@__anvill_stack_minus_91 = global i8 0
@__anvill_stack_minus_90 = global i8 0
@__anvill_stack_minus_89 = global i8 0
@__anvill_stack_minus_88 = global i8 0
@__anvill_stack_minus_87 = global i8 0
@__anvill_stack_minus_86 = global i8 0
@__anvill_stack_minus_85 = global i8 0
@__anvill_stack_minus_84 = global i8 0
@__anvill_stack_minus_83 = global i8 0
@__anvill_stack_minus_82 = global i8 0
@__anvill_stack_minus_81 = global i8 0
@__anvill_stack_minus_80 = global i8 0
@__anvill_stack_minus_79 = global i8 0
@__anvill_stack_minus_78 = global i8 0
@__anvill_stack_minus_77 = global i8 0
@__anvill_stack_minus_76 = global i8 0
@__anvill_stack_minus_75 = global i8 0
@__anvill_stack_minus_74 = global i8 0
@__anvill_stack_minus_73 = global i8 0
@__anvill_stack_minus_72 = global i8 0
@__anvill_stack_minus_71 = global i8 0
@__anvill_stack_minus_70 = global i8 0
@__anvill_stack_minus_69 = global i8 0
@__anvill_stack_minus_68 = global i8 0
@__anvill_stack_minus_67 = global i8 0
@__anvill_stack_minus_66 = global i8 0
@__anvill_stack_minus_65 = global i8 0
@__anvill_stack_minus_64 = global i8 0
@__anvill_stack_minus_63 = global i8 0
@__anvill_stack_minus_62 = global i8 0
@__anvill_stack_minus_61 = global i8 0
@__anvill_stack_minus_60 = global i8 0
@__anvill_stack_minus_59 = global i8 0
@__anvill_stack_minus_58 = global i8 0
@__anvill_stack_minus_57 = global i8 0
@__anvill_stack_minus_56 = global i8 0
@__anvill_stack_minus_55 = global i8 0
@__anvill_stack_minus_54 = global i8 0
@__anvill_stack_minus_53 = global i8 0
@__anvill_stack_minus_52 = global i8 0
@__anvill_stack_minus_51 = global i8 0
@__anvill_stack_minus_50 = global i8 0
@__anvill_stack_minus_49 = global i8 0
@__anvill_stack_minus_48 = global i8 0
@__anvill_stack_minus_47 = global i8 0
@__anvill_stack_minus_46 = global i8 0
@__anvill_stack_minus_45 = global i8 0
@__anvill_stack_minus_44 = global i8 0
@__anvill_stack_minus_43 = global i8 0
@__anvill_stack_minus_42 = global i8 0
@__anvill_stack_minus_41 = global i8 0
@__anvill_stack_minus_40 = global i8 0
@__anvill_stack_minus_39 = global i8 0
@__anvill_stack_minus_38 = global i8 0
@__anvill_stack_minus_37 = global i8 0
@__anvill_stack_minus_36 = global i8 0
@__anvill_stack_minus_35 = global i8 0
@__anvill_stack_minus_34 = global i8 0
@__anvill_stack_minus_33 = global i8 0
@__anvill_stack_minus_32 = global i8 0
@__anvill_stack_minus_31 = global i8 0
@__anvill_stack_minus_30 = global i8 0
@__anvill_stack_minus_29 = global i8 0
@__anvill_stack_minus_28 = global i8 0
@__anvill_stack_minus_27 = global i8 0
@__anvill_stack_minus_26 = global i8 0
@__anvill_stack_minus_25 = global i8 0
@__anvill_stack_minus_24 = global i8 0
@__anvill_stack_minus_23 = global i8 0
@__anvill_stack_minus_22 = global i8 0
@__anvill_stack_minus_21 = global i8 0
@__anvill_stack_minus_20 = global i8 0
@__anvill_stack_minus_19 = global i8 0
@__anvill_stack_minus_18 = global i8 0
@__anvill_stack_minus_17 = global i8 0
@__anvill_stack_minus_16 = global i8 0
@__anvill_stack_minus_15 = global i8 0
@__anvill_stack_minus_14 = global i8 0
@__anvill_stack_minus_13 = global i8 0
@__anvill_stack_minus_12 = global i8 0
@__anvill_stack_minus_11 = global i8 0
@__anvill_stack_minus_10 = global i8 0
@__anvill_stack_minus_9 = global i8 0
@__anvill_stack_minus_8 = global i8 0
@__anvill_stack_minus_7 = global i8 0
@__anvill_stack_minus_6 = global i8 0
@__anvill_stack_minus_5 = global i8 0
@__anvill_stack_minus_4 = global i8 0
@__anvill_stack_minus_3 = global i8 0
@__anvill_stack_minus_2 = global i8 0
@__anvill_stack_minus_1 = global i8 0
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0

; Function Attrs: noinline
declare i64 @sub_4011a4__All_Svl_B_0(i64, i64, ptr) #0

; Function Attrs: noinline
declare ptr @sub_401030__A_Sb_Sb_Sb_B_0(ptr, ptr) #0

; Function Attrs: noinline
declare i32 @sub_401040__A_Sbi_B_0(ptr) #0

; Function Attrs: noinline
declare i32 @sub_401050__Aiii_Sbii_B_0(i32, i32, i32, ptr, i32) #0

; Function Attrs: noinline
declare i64 @sub_401060__Ai_Sbll_B_0(i32, ptr, i64) #0

; Function Attrs: noinline
declare i64 @sub_401070__Avl_B_0() #0

; Function Attrs: noinline
declare ptr @sub_401080__A_Sl_Sb_B_0(ptr) #0

; Function Attrs: noinline
declare i32 @sub_401090__A_Sb_Vi_B_0(ptr, ...) #0

; Function Attrs: noinline
declare i32 @sub_4010a0__A_Sbl_Sb_Vi_B_0(ptr, i64, ptr, ...) #0

; Function Attrs: noinline
declare i64 @sub_4010b0__Ailil_B_0(i32, i64, i32) #0

; Function Attrs: noinline
declare i32 @sub_4010c0__Ail_Vi_B_0(i32, i64, ...) #0

; Function Attrs: noinline
declare i64 @sub_4010d0__Ai_Sbll_B_0(i32, ptr, i64) #0

; Function Attrs: noinline
declare i32 @sub_4010e0__A_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_Sb_Vi_B_0(ptr, ptr, ...) #0

; Function Attrs: noinline
declare i64 @sub_4010f0__A_Sll_B_0(ptr) #0

; Function Attrs: noinline
declare i32 @sub_401100__Ai_S_X0_E_Clx16_D_F_S_X1_E_Clx16_D_F_S_X2_E_Clx16_D_F_S_X3_Ell_Fi_B_0(i32, ptr, ptr, ptr, ptr) #0

; Function Attrs: noinline
declare i64 @sub_401110__All_B_0(i64) #0

; Function Attrs: noinline
declare i32 @sub_401120__Ai_S_X0_Eh_Cbx14_D_Fii_B_0(i32, ptr, i32) #0

; Function Attrs: noinline
declare i32 @sub_401130__A_Sbi_Vi_B_0(ptr, i32, ...) #0

; Function Attrs: noinline
declare ptr @sub_401140__A_Sb_Sb_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_B_0(ptr, ptr) #0

; Function Attrs: noinline
declare void @sub_401150__A_Sbv_B_0(ptr) #0

; Function Attrs: noinline
declare i32 @sub_401160__Aii_B_0(i32) #0

; Function Attrs: noinline
declare i32 @sub_401170__Aiiii_B_0(i32, i32, i32) #0

; Function Attrs: noinline
declare i64 @sub_401b80__A_Sll_B_0(ptr) #0

; Function Attrs: noinline
declare i64 @sub_401610__A_Si_Sbl_B_0(ptr, ptr) #0

; Function Attrs: noinline
declare i64 @sub_401690__A_Sb_Sbl_B_0(ptr, ptr) #0

; Function Attrs: noinline
declare i64 @sub_401920__Aiil_B_0(i32, i32) #0

; Function Attrs: noinline
declare void @sub_401cd0__A_Sbv_B_0(ptr) #0

; Function Attrs: noinline
declare i64 @sub_4016d0__A_Sb_Sbl_B_0(ptr, ptr) #0

; Function Attrs: noinline
declare i64 @sub_4016e0__Avl_B_0() #0

; Function Attrs: noinline
declare i64 @sub_401c60__A_Sbl_B_0(ptr) #0

; Function Attrs: noinline
declare i64 @sub_401a70__Ailil_B_0(i32, i64, i32) #0

; Function Attrs: noinline
declare i64 @sub_401af0__Aiil_B_0(i32, i32) #0

; Function Attrs: noinline
define i32 @sub_401270__Ai_S_Sb_S_Sbi_B_0(i32 %0, ptr %1, ptr %2) #0 {
  %4 = alloca %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, align 8
  %5 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 0
  %6 = load i8, ptr @__anvill_stack_minus_368, align 1
  store i8 %6, ptr %5, align 8
  %7 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 1
  %8 = load i8, ptr @__anvill_stack_minus_367, align 1
  store i8 %8, ptr %7, align 1
  %9 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 2
  %10 = load i8, ptr @__anvill_stack_minus_366, align 1
  store i8 %10, ptr %9, align 2
  %11 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 3
  %12 = load i8, ptr @__anvill_stack_minus_365, align 1
  store i8 %12, ptr %11, align 1
  %13 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 4
  %14 = load i8, ptr @__anvill_stack_minus_364, align 1
  store i8 %14, ptr %13, align 4
  %15 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 5
  %16 = load i8, ptr @__anvill_stack_minus_363, align 1
  store i8 %16, ptr %15, align 1
  %17 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 6
  %18 = load i8, ptr @__anvill_stack_minus_362, align 1
  store i8 %18, ptr %17, align 2
  %19 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 7
  %20 = load i8, ptr @__anvill_stack_minus_361, align 1
  store i8 %20, ptr %19, align 1
  %21 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 8
  %22 = load i8, ptr @__anvill_stack_minus_360, align 1
  store i8 %22, ptr %21, align 8
  %23 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 9
  %24 = load i8, ptr @__anvill_stack_minus_359, align 1
  store i8 %24, ptr %23, align 1
  %25 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 10
  %26 = load i8, ptr @__anvill_stack_minus_358, align 1
  store i8 %26, ptr %25, align 2
  %27 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 11
  %28 = load i8, ptr @__anvill_stack_minus_357, align 1
  store i8 %28, ptr %27, align 1
  %29 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 12
  %30 = load i8, ptr @__anvill_stack_minus_356, align 1
  store i8 %30, ptr %29, align 4
  %31 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 13
  %32 = load i8, ptr @__anvill_stack_minus_355, align 1
  store i8 %32, ptr %31, align 1
  %33 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 14
  %34 = load i8, ptr @__anvill_stack_minus_354, align 1
  store i8 %34, ptr %33, align 2
  %35 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 15
  %36 = load i8, ptr @__anvill_stack_minus_353, align 1
  store i8 %36, ptr %35, align 1
  %37 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 16
  %38 = load i8, ptr @__anvill_stack_minus_352, align 1
  store i8 %38, ptr %37, align 8
  %39 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 17
  %40 = load i8, ptr @__anvill_stack_minus_351, align 1
  store i8 %40, ptr %39, align 1
  %41 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 18
  %42 = load i8, ptr @__anvill_stack_minus_350, align 1
  store i8 %42, ptr %41, align 2
  %43 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 19
  %44 = load i8, ptr @__anvill_stack_minus_349, align 1
  store i8 %44, ptr %43, align 1
  %45 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 20
  %46 = load i8, ptr @__anvill_stack_minus_348, align 1
  store i8 %46, ptr %45, align 4
  %47 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 21
  %48 = load i8, ptr @__anvill_stack_minus_347, align 1
  store i8 %48, ptr %47, align 1
  %49 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 22
  %50 = load i8, ptr @__anvill_stack_minus_346, align 1
  store i8 %50, ptr %49, align 2
  %51 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 23
  %52 = load i8, ptr @__anvill_stack_minus_345, align 1
  store i8 %52, ptr %51, align 1
  %53 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 24
  %54 = load i8, ptr @__anvill_stack_minus_344, align 1
  store i8 %54, ptr %53, align 8
  %55 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 25
  %56 = load i8, ptr @__anvill_stack_minus_343, align 1
  store i8 %56, ptr %55, align 1
  %57 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 26
  %58 = load i8, ptr @__anvill_stack_minus_342, align 1
  store i8 %58, ptr %57, align 2
  %59 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 27
  %60 = load i8, ptr @__anvill_stack_minus_341, align 1
  store i8 %60, ptr %59, align 1
  %61 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 28
  %62 = load i8, ptr @__anvill_stack_minus_340, align 1
  store i8 %62, ptr %61, align 4
  %63 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 29
  %64 = load i8, ptr @__anvill_stack_minus_339, align 1
  store i8 %64, ptr %63, align 1
  %65 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 30
  %66 = load i8, ptr @__anvill_stack_minus_338, align 1
  store i8 %66, ptr %65, align 2
  %67 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 31
  %68 = load i8, ptr @__anvill_stack_minus_337, align 1
  store i8 %68, ptr %67, align 1
  %69 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 32
  %70 = load i8, ptr @__anvill_stack_minus_336, align 1
  store i8 %70, ptr %69, align 8
  %71 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 33
  %72 = load i8, ptr @__anvill_stack_minus_335, align 1
  store i8 %72, ptr %71, align 1
  %73 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 34
  %74 = load i8, ptr @__anvill_stack_minus_334, align 1
  store i8 %74, ptr %73, align 2
  %75 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 35
  %76 = load i8, ptr @__anvill_stack_minus_333, align 1
  store i8 %76, ptr %75, align 1
  %77 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 36
  %78 = load i8, ptr @__anvill_stack_minus_332, align 1
  store i8 %78, ptr %77, align 4
  %79 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 37
  %80 = load i8, ptr @__anvill_stack_minus_331, align 1
  store i8 %80, ptr %79, align 1
  %81 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 38
  %82 = load i8, ptr @__anvill_stack_minus_330, align 1
  store i8 %82, ptr %81, align 2
  %83 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 39
  %84 = load i8, ptr @__anvill_stack_minus_329, align 1
  store i8 %84, ptr %83, align 1
  %85 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 40
  %86 = load i8, ptr @__anvill_stack_minus_328, align 1
  store i8 %86, ptr %85, align 8
  %87 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 41
  %88 = load i8, ptr @__anvill_stack_minus_327, align 1
  store i8 %88, ptr %87, align 1
  %89 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 42
  %90 = load i8, ptr @__anvill_stack_minus_326, align 1
  store i8 %90, ptr %89, align 2
  %91 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 43
  %92 = load i8, ptr @__anvill_stack_minus_325, align 1
  store i8 %92, ptr %91, align 1
  %93 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 44
  %94 = load i8, ptr @__anvill_stack_minus_324, align 1
  store i8 %94, ptr %93, align 4
  %95 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 45
  %96 = load i8, ptr @__anvill_stack_minus_323, align 1
  store i8 %96, ptr %95, align 1
  %97 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 46
  %98 = load i8, ptr @__anvill_stack_minus_322, align 1
  store i8 %98, ptr %97, align 2
  %99 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 47
  %100 = load i8, ptr @__anvill_stack_minus_321, align 1
  store i8 %100, ptr %99, align 1
  %101 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 48
  %102 = load i8, ptr @__anvill_stack_minus_320, align 1
  store i8 %102, ptr %101, align 8
  %103 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 49
  %104 = load i8, ptr @__anvill_stack_minus_319, align 1
  store i8 %104, ptr %103, align 1
  %105 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 50
  %106 = load i8, ptr @__anvill_stack_minus_318, align 1
  store i8 %106, ptr %105, align 2
  %107 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 51
  %108 = load i8, ptr @__anvill_stack_minus_317, align 1
  store i8 %108, ptr %107, align 1
  %109 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 52
  %110 = load i8, ptr @__anvill_stack_minus_316, align 1
  store i8 %110, ptr %109, align 4
  %111 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 53
  %112 = load i8, ptr @__anvill_stack_minus_315, align 1
  store i8 %112, ptr %111, align 1
  %113 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 54
  %114 = load i8, ptr @__anvill_stack_minus_314, align 1
  store i8 %114, ptr %113, align 2
  %115 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 55
  %116 = load i8, ptr @__anvill_stack_minus_313, align 1
  store i8 %116, ptr %115, align 1
  %117 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 56
  %118 = load i8, ptr @__anvill_stack_minus_312, align 1
  store i8 %118, ptr %117, align 8
  %119 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 57
  %120 = load i8, ptr @__anvill_stack_minus_311, align 1
  store i8 %120, ptr %119, align 1
  %121 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 58
  %122 = load i8, ptr @__anvill_stack_minus_310, align 1
  store i8 %122, ptr %121, align 2
  %123 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 59
  %124 = load i8, ptr @__anvill_stack_minus_309, align 1
  store i8 %124, ptr %123, align 1
  %125 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 60
  %126 = load i8, ptr @__anvill_stack_minus_308, align 1
  store i8 %126, ptr %125, align 4
  %127 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 61
  %128 = load i8, ptr @__anvill_stack_minus_307, align 1
  store i8 %128, ptr %127, align 1
  %129 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 62
  %130 = load i8, ptr @__anvill_stack_minus_306, align 1
  store i8 %130, ptr %129, align 2
  %131 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 63
  %132 = load i8, ptr @__anvill_stack_minus_305, align 1
  store i8 %132, ptr %131, align 1
  %133 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 64
  %134 = load i8, ptr @__anvill_stack_minus_304, align 1
  store i8 %134, ptr %133, align 8
  %135 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 65
  %136 = load i8, ptr @__anvill_stack_minus_303, align 1
  store i8 %136, ptr %135, align 1
  %137 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 66
  %138 = load i8, ptr @__anvill_stack_minus_302, align 1
  store i8 %138, ptr %137, align 2
  %139 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 67
  %140 = load i8, ptr @__anvill_stack_minus_301, align 1
  store i8 %140, ptr %139, align 1
  %141 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 68
  %142 = load i8, ptr @__anvill_stack_minus_300, align 1
  store i8 %142, ptr %141, align 4
  %143 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 69
  %144 = load i8, ptr @__anvill_stack_minus_299, align 1
  store i8 %144, ptr %143, align 1
  %145 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 70
  %146 = load i8, ptr @__anvill_stack_minus_298, align 1
  store i8 %146, ptr %145, align 2
  %147 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 71
  %148 = load i8, ptr @__anvill_stack_minus_297, align 1
  store i8 %148, ptr %147, align 1
  %149 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 72
  %150 = load i8, ptr @__anvill_stack_minus_296, align 1
  store i8 %150, ptr %149, align 8
  %151 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 73
  %152 = load i8, ptr @__anvill_stack_minus_295, align 1
  store i8 %152, ptr %151, align 1
  %153 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 74
  %154 = load i8, ptr @__anvill_stack_minus_294, align 1
  store i8 %154, ptr %153, align 2
  %155 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 75
  %156 = load i8, ptr @__anvill_stack_minus_293, align 1
  store i8 %156, ptr %155, align 1
  %157 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 76
  %158 = load i8, ptr @__anvill_stack_minus_292, align 1
  store i8 %158, ptr %157, align 4
  %159 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 77
  %160 = load i8, ptr @__anvill_stack_minus_291, align 1
  store i8 %160, ptr %159, align 1
  %161 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 78
  %162 = load i8, ptr @__anvill_stack_minus_290, align 1
  store i8 %162, ptr %161, align 2
  %163 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 79
  %164 = load i8, ptr @__anvill_stack_minus_289, align 1
  store i8 %164, ptr %163, align 1
  %165 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 80
  %166 = load i8, ptr @__anvill_stack_minus_288, align 1
  store i8 %166, ptr %165, align 8
  %167 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 81
  %168 = load i8, ptr @__anvill_stack_minus_287, align 1
  store i8 %168, ptr %167, align 1
  %169 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 82
  %170 = load i8, ptr @__anvill_stack_minus_286, align 1
  store i8 %170, ptr %169, align 2
  %171 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 83
  %172 = load i8, ptr @__anvill_stack_minus_285, align 1
  store i8 %172, ptr %171, align 1
  %173 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 84
  %174 = load i8, ptr @__anvill_stack_minus_284, align 1
  store i8 %174, ptr %173, align 4
  %175 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 85
  %176 = load i8, ptr @__anvill_stack_minus_283, align 1
  store i8 %176, ptr %175, align 1
  %177 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 86
  %178 = load i8, ptr @__anvill_stack_minus_282, align 1
  store i8 %178, ptr %177, align 2
  %179 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 87
  %180 = load i8, ptr @__anvill_stack_minus_281, align 1
  store i8 %180, ptr %179, align 1
  %181 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 88
  %182 = load i8, ptr @__anvill_stack_minus_280, align 1
  store i8 %182, ptr %181, align 8
  %183 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 89
  %184 = load i8, ptr @__anvill_stack_minus_279, align 1
  store i8 %184, ptr %183, align 1
  %185 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 90
  %186 = load i8, ptr @__anvill_stack_minus_278, align 1
  store i8 %186, ptr %185, align 2
  %187 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 91
  %188 = load i8, ptr @__anvill_stack_minus_277, align 1
  store i8 %188, ptr %187, align 1
  %189 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 92
  %190 = load i8, ptr @__anvill_stack_minus_276, align 1
  store i8 %190, ptr %189, align 4
  %191 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 93
  %192 = load i8, ptr @__anvill_stack_minus_275, align 1
  store i8 %192, ptr %191, align 1
  %193 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 94
  %194 = load i8, ptr @__anvill_stack_minus_274, align 1
  store i8 %194, ptr %193, align 2
  %195 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 95
  %196 = load i8, ptr @__anvill_stack_minus_273, align 1
  store i8 %196, ptr %195, align 1
  %197 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 96
  %198 = load i8, ptr @__anvill_stack_minus_272, align 1
  store i8 %198, ptr %197, align 8
  %199 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 97
  %200 = load i8, ptr @__anvill_stack_minus_271, align 1
  store i8 %200, ptr %199, align 1
  %201 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 98
  %202 = load i8, ptr @__anvill_stack_minus_270, align 1
  store i8 %202, ptr %201, align 2
  %203 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 99
  %204 = load i8, ptr @__anvill_stack_minus_269, align 1
  store i8 %204, ptr %203, align 1
  %205 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 100
  %206 = load i8, ptr @__anvill_stack_minus_268, align 1
  store i8 %206, ptr %205, align 4
  %207 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 101
  %208 = load i8, ptr @__anvill_stack_minus_267, align 1
  store i8 %208, ptr %207, align 1
  %209 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 102
  %210 = load i8, ptr @__anvill_stack_minus_266, align 1
  store i8 %210, ptr %209, align 2
  %211 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 103
  %212 = load i8, ptr @__anvill_stack_minus_265, align 1
  store i8 %212, ptr %211, align 1
  %213 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 104
  %214 = load i8, ptr @__anvill_stack_minus_264, align 1
  store i8 %214, ptr %213, align 8
  %215 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 105
  %216 = load i8, ptr @__anvill_stack_minus_263, align 1
  store i8 %216, ptr %215, align 1
  %217 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 106
  %218 = load i8, ptr @__anvill_stack_minus_262, align 1
  store i8 %218, ptr %217, align 2
  %219 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 107
  %220 = load i8, ptr @__anvill_stack_minus_261, align 1
  store i8 %220, ptr %219, align 1
  %221 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 108
  %222 = load i8, ptr @__anvill_stack_minus_260, align 1
  store i8 %222, ptr %221, align 4
  %223 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 109
  %224 = load i8, ptr @__anvill_stack_minus_259, align 1
  store i8 %224, ptr %223, align 1
  %225 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 110
  %226 = load i8, ptr @__anvill_stack_minus_258, align 1
  store i8 %226, ptr %225, align 2
  %227 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 111
  %228 = load i8, ptr @__anvill_stack_minus_257, align 1
  store i8 %228, ptr %227, align 1
  %229 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 112
  %230 = load i8, ptr @__anvill_stack_minus_256, align 1
  store i8 %230, ptr %229, align 8
  %231 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 113
  %232 = load i8, ptr @__anvill_stack_minus_255, align 1
  store i8 %232, ptr %231, align 1
  %233 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 114
  %234 = load i8, ptr @__anvill_stack_minus_254, align 1
  store i8 %234, ptr %233, align 2
  %235 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 115
  %236 = load i8, ptr @__anvill_stack_minus_253, align 1
  store i8 %236, ptr %235, align 1
  %237 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 116
  %238 = load i8, ptr @__anvill_stack_minus_252, align 1
  store i8 %238, ptr %237, align 4
  %239 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 117
  %240 = load i8, ptr @__anvill_stack_minus_251, align 1
  store i8 %240, ptr %239, align 1
  %241 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 118
  %242 = load i8, ptr @__anvill_stack_minus_250, align 1
  store i8 %242, ptr %241, align 2
  %243 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 119
  %244 = load i8, ptr @__anvill_stack_minus_249, align 1
  store i8 %244, ptr %243, align 1
  %245 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 120
  %246 = load i8, ptr @__anvill_stack_minus_248, align 1
  store i8 %246, ptr %245, align 8
  %247 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 121
  %248 = load i8, ptr @__anvill_stack_minus_247, align 1
  store i8 %248, ptr %247, align 1
  %249 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 122
  %250 = load i8, ptr @__anvill_stack_minus_246, align 1
  store i8 %250, ptr %249, align 2
  %251 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 123
  %252 = load i8, ptr @__anvill_stack_minus_245, align 1
  store i8 %252, ptr %251, align 1
  %253 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 124
  %254 = load i8, ptr @__anvill_stack_minus_244, align 1
  store i8 %254, ptr %253, align 4
  %255 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 125
  %256 = load i8, ptr @__anvill_stack_minus_243, align 1
  store i8 %256, ptr %255, align 1
  %257 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 126
  %258 = load i8, ptr @__anvill_stack_minus_242, align 1
  store i8 %258, ptr %257, align 2
  %259 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 127
  %260 = load i8, ptr @__anvill_stack_minus_241, align 1
  store i8 %260, ptr %259, align 1
  %261 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 128
  %262 = load i8, ptr @__anvill_stack_minus_240, align 1
  store i8 %262, ptr %261, align 8
  %263 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 129
  %264 = load i8, ptr @__anvill_stack_minus_239, align 1
  store i8 %264, ptr %263, align 1
  %265 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 130
  %266 = load i8, ptr @__anvill_stack_minus_238, align 1
  store i8 %266, ptr %265, align 2
  %267 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 131
  %268 = load i8, ptr @__anvill_stack_minus_237, align 1
  store i8 %268, ptr %267, align 1
  %269 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 132
  %270 = load i8, ptr @__anvill_stack_minus_236, align 1
  store i8 %270, ptr %269, align 4
  %271 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 133
  %272 = load i8, ptr @__anvill_stack_minus_235, align 1
  store i8 %272, ptr %271, align 1
  %273 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 134
  %274 = load i8, ptr @__anvill_stack_minus_234, align 1
  store i8 %274, ptr %273, align 2
  %275 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 135
  %276 = load i8, ptr @__anvill_stack_minus_233, align 1
  store i8 %276, ptr %275, align 1
  %277 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 136
  %278 = load i8, ptr @__anvill_stack_minus_232, align 1
  store i8 %278, ptr %277, align 8
  %279 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 137
  %280 = load i8, ptr @__anvill_stack_minus_231, align 1
  store i8 %280, ptr %279, align 1
  %281 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 138
  %282 = load i8, ptr @__anvill_stack_minus_230, align 1
  store i8 %282, ptr %281, align 2
  %283 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 139
  %284 = load i8, ptr @__anvill_stack_minus_229, align 1
  store i8 %284, ptr %283, align 1
  %285 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 140
  %286 = load i8, ptr @__anvill_stack_minus_228, align 1
  store i8 %286, ptr %285, align 4
  %287 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 141
  %288 = load i8, ptr @__anvill_stack_minus_227, align 1
  store i8 %288, ptr %287, align 1
  %289 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 142
  %290 = load i8, ptr @__anvill_stack_minus_226, align 1
  store i8 %290, ptr %289, align 2
  %291 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 143
  %292 = load i8, ptr @__anvill_stack_minus_225, align 1
  store i8 %292, ptr %291, align 1
  %293 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 144
  %294 = load i8, ptr @__anvill_stack_minus_224, align 1
  store i8 %294, ptr %293, align 8
  %295 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 145
  %296 = load i8, ptr @__anvill_stack_minus_223, align 1
  store i8 %296, ptr %295, align 1
  %297 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 146
  %298 = load i8, ptr @__anvill_stack_minus_222, align 1
  store i8 %298, ptr %297, align 2
  %299 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 147
  %300 = load i8, ptr @__anvill_stack_minus_221, align 1
  store i8 %300, ptr %299, align 1
  %301 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 148
  %302 = load i8, ptr @__anvill_stack_minus_220, align 1
  store i8 %302, ptr %301, align 4
  %303 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 149
  %304 = load i8, ptr @__anvill_stack_minus_219, align 1
  store i8 %304, ptr %303, align 1
  %305 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 150
  %306 = load i8, ptr @__anvill_stack_minus_218, align 1
  store i8 %306, ptr %305, align 2
  %307 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 151
  %308 = load i8, ptr @__anvill_stack_minus_217, align 1
  store i8 %308, ptr %307, align 1
  %309 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 152
  %310 = load i8, ptr @__anvill_stack_minus_216, align 1
  store i8 %310, ptr %309, align 8
  %311 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 153
  %312 = load i8, ptr @__anvill_stack_minus_215, align 1
  store i8 %312, ptr %311, align 1
  %313 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 154
  %314 = load i8, ptr @__anvill_stack_minus_214, align 1
  store i8 %314, ptr %313, align 2
  %315 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 155
  %316 = load i8, ptr @__anvill_stack_minus_213, align 1
  store i8 %316, ptr %315, align 1
  %317 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 156
  %318 = load i8, ptr @__anvill_stack_minus_212, align 1
  store i8 %318, ptr %317, align 4
  %319 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 157
  %320 = load i8, ptr @__anvill_stack_minus_211, align 1
  store i8 %320, ptr %319, align 1
  %321 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 158
  %322 = load i8, ptr @__anvill_stack_minus_210, align 1
  store i8 %322, ptr %321, align 2
  %323 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 159
  %324 = load i8, ptr @__anvill_stack_minus_209, align 1
  store i8 %324, ptr %323, align 1
  %325 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 160
  %326 = load i8, ptr @__anvill_stack_minus_208, align 1
  store i8 %326, ptr %325, align 8
  %327 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 161
  %328 = load i8, ptr @__anvill_stack_minus_207, align 1
  store i8 %328, ptr %327, align 1
  %329 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 162
  %330 = load i8, ptr @__anvill_stack_minus_206, align 1
  store i8 %330, ptr %329, align 2
  %331 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 163
  %332 = load i8, ptr @__anvill_stack_minus_205, align 1
  store i8 %332, ptr %331, align 1
  %333 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 164
  %334 = load i8, ptr @__anvill_stack_minus_204, align 1
  store i8 %334, ptr %333, align 4
  %335 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 165
  %336 = load i8, ptr @__anvill_stack_minus_203, align 1
  store i8 %336, ptr %335, align 1
  %337 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 166
  %338 = load i8, ptr @__anvill_stack_minus_202, align 1
  store i8 %338, ptr %337, align 2
  %339 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 167
  %340 = load i8, ptr @__anvill_stack_minus_201, align 1
  store i8 %340, ptr %339, align 1
  %341 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 168
  %342 = load i8, ptr @__anvill_stack_minus_200, align 1
  store i8 %342, ptr %341, align 8
  %343 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 169
  %344 = load i8, ptr @__anvill_stack_minus_199, align 1
  store i8 %344, ptr %343, align 1
  %345 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 170
  %346 = load i8, ptr @__anvill_stack_minus_198, align 1
  store i8 %346, ptr %345, align 2
  %347 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 171
  %348 = load i8, ptr @__anvill_stack_minus_197, align 1
  store i8 %348, ptr %347, align 1
  %349 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 172
  %350 = load i8, ptr @__anvill_stack_minus_196, align 1
  store i8 %350, ptr %349, align 4
  %351 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 173
  %352 = load i8, ptr @__anvill_stack_minus_195, align 1
  store i8 %352, ptr %351, align 1
  %353 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 174
  %354 = load i8, ptr @__anvill_stack_minus_194, align 1
  store i8 %354, ptr %353, align 2
  %355 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 175
  %356 = load i8, ptr @__anvill_stack_minus_193, align 1
  store i8 %356, ptr %355, align 1
  %357 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 176
  %358 = load i8, ptr @__anvill_stack_minus_192, align 1
  store i8 %358, ptr %357, align 8
  %359 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 177
  %360 = load i8, ptr @__anvill_stack_minus_191, align 1
  store i8 %360, ptr %359, align 1
  %361 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 178
  %362 = load i8, ptr @__anvill_stack_minus_190, align 1
  store i8 %362, ptr %361, align 2
  %363 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 179
  %364 = load i8, ptr @__anvill_stack_minus_189, align 1
  store i8 %364, ptr %363, align 1
  %365 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 180
  %366 = load i8, ptr @__anvill_stack_minus_188, align 1
  store i8 %366, ptr %365, align 4
  %367 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 181
  %368 = load i8, ptr @__anvill_stack_minus_187, align 1
  store i8 %368, ptr %367, align 1
  %369 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 182
  %370 = load i8, ptr @__anvill_stack_minus_186, align 1
  store i8 %370, ptr %369, align 2
  %371 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 183
  %372 = load i8, ptr @__anvill_stack_minus_185, align 1
  store i8 %372, ptr %371, align 1
  %373 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 184
  %374 = load i8, ptr @__anvill_stack_minus_184, align 1
  store i8 %374, ptr %373, align 8
  %375 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 185
  %376 = load i8, ptr @__anvill_stack_minus_183, align 1
  store i8 %376, ptr %375, align 1
  %377 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 186
  %378 = load i8, ptr @__anvill_stack_minus_182, align 1
  store i8 %378, ptr %377, align 2
  %379 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 187
  %380 = load i8, ptr @__anvill_stack_minus_181, align 1
  store i8 %380, ptr %379, align 1
  %381 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 188
  %382 = load i8, ptr @__anvill_stack_minus_180, align 1
  store i8 %382, ptr %381, align 4
  %383 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 189
  %384 = load i8, ptr @__anvill_stack_minus_179, align 1
  store i8 %384, ptr %383, align 1
  %385 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 190
  %386 = load i8, ptr @__anvill_stack_minus_178, align 1
  store i8 %386, ptr %385, align 2
  %387 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 191
  %388 = load i8, ptr @__anvill_stack_minus_177, align 1
  store i8 %388, ptr %387, align 1
  %389 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 192
  %390 = load i8, ptr @__anvill_stack_minus_176, align 1
  store i8 %390, ptr %389, align 8
  %391 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 193
  %392 = load i8, ptr @__anvill_stack_minus_175, align 1
  store i8 %392, ptr %391, align 1
  %393 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 194
  %394 = load i8, ptr @__anvill_stack_minus_174, align 1
  store i8 %394, ptr %393, align 2
  %395 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 195
  %396 = load i8, ptr @__anvill_stack_minus_173, align 1
  store i8 %396, ptr %395, align 1
  %397 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 196
  %398 = load i8, ptr @__anvill_stack_minus_172, align 1
  store i8 %398, ptr %397, align 4
  %399 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 197
  %400 = load i8, ptr @__anvill_stack_minus_171, align 1
  store i8 %400, ptr %399, align 1
  %401 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 198
  %402 = load i8, ptr @__anvill_stack_minus_170, align 1
  store i8 %402, ptr %401, align 2
  %403 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 199
  %404 = load i8, ptr @__anvill_stack_minus_169, align 1
  store i8 %404, ptr %403, align 1
  %405 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 200
  %406 = load i8, ptr @__anvill_stack_minus_168, align 1
  store i8 %406, ptr %405, align 8
  %407 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 201
  %408 = load i8, ptr @__anvill_stack_minus_167, align 1
  store i8 %408, ptr %407, align 1
  %409 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 202
  %410 = load i8, ptr @__anvill_stack_minus_166, align 1
  store i8 %410, ptr %409, align 2
  %411 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 203
  %412 = load i8, ptr @__anvill_stack_minus_165, align 1
  store i8 %412, ptr %411, align 1
  %413 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 204
  %414 = load i8, ptr @__anvill_stack_minus_164, align 1
  store i8 %414, ptr %413, align 4
  %415 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 205
  %416 = load i8, ptr @__anvill_stack_minus_163, align 1
  store i8 %416, ptr %415, align 1
  %417 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 206
  %418 = load i8, ptr @__anvill_stack_minus_162, align 1
  store i8 %418, ptr %417, align 2
  %419 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 207
  %420 = load i8, ptr @__anvill_stack_minus_161, align 1
  store i8 %420, ptr %419, align 1
  %421 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 208
  %422 = load i8, ptr @__anvill_stack_minus_160, align 1
  store i8 %422, ptr %421, align 8
  %423 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 209
  %424 = load i8, ptr @__anvill_stack_minus_159, align 1
  store i8 %424, ptr %423, align 1
  %425 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 210
  %426 = load i8, ptr @__anvill_stack_minus_158, align 1
  store i8 %426, ptr %425, align 2
  %427 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 211
  %428 = load i8, ptr @__anvill_stack_minus_157, align 1
  store i8 %428, ptr %427, align 1
  %429 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 212
  %430 = load i8, ptr @__anvill_stack_minus_156, align 1
  store i8 %430, ptr %429, align 4
  %431 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 213
  %432 = load i8, ptr @__anvill_stack_minus_155, align 1
  store i8 %432, ptr %431, align 1
  %433 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 214
  %434 = load i8, ptr @__anvill_stack_minus_154, align 1
  store i8 %434, ptr %433, align 2
  %435 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 215
  %436 = load i8, ptr @__anvill_stack_minus_153, align 1
  store i8 %436, ptr %435, align 1
  %437 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 216
  %438 = load i8, ptr @__anvill_stack_minus_152, align 1
  store i8 %438, ptr %437, align 8
  %439 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 217
  %440 = load i8, ptr @__anvill_stack_minus_151, align 1
  store i8 %440, ptr %439, align 1
  %441 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 218
  %442 = load i8, ptr @__anvill_stack_minus_150, align 1
  store i8 %442, ptr %441, align 2
  %443 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 219
  %444 = load i8, ptr @__anvill_stack_minus_149, align 1
  store i8 %444, ptr %443, align 1
  %445 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 220
  %446 = load i8, ptr @__anvill_stack_minus_148, align 1
  store i8 %446, ptr %445, align 4
  %447 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 221
  %448 = load i8, ptr @__anvill_stack_minus_147, align 1
  store i8 %448, ptr %447, align 1
  %449 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 222
  %450 = load i8, ptr @__anvill_stack_minus_146, align 1
  store i8 %450, ptr %449, align 2
  %451 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 223
  %452 = load i8, ptr @__anvill_stack_minus_145, align 1
  store i8 %452, ptr %451, align 1
  %453 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 224
  %454 = load i8, ptr @__anvill_stack_minus_144, align 1
  store i8 %454, ptr %453, align 8
  %455 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 225
  %456 = load i8, ptr @__anvill_stack_minus_143, align 1
  store i8 %456, ptr %455, align 1
  %457 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 226
  %458 = load i8, ptr @__anvill_stack_minus_142, align 1
  store i8 %458, ptr %457, align 2
  %459 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 227
  %460 = load i8, ptr @__anvill_stack_minus_141, align 1
  store i8 %460, ptr %459, align 1
  %461 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 228
  %462 = load i8, ptr @__anvill_stack_minus_140, align 1
  store i8 %462, ptr %461, align 4
  %463 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 229
  %464 = load i8, ptr @__anvill_stack_minus_139, align 1
  store i8 %464, ptr %463, align 1
  %465 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 230
  %466 = load i8, ptr @__anvill_stack_minus_138, align 1
  store i8 %466, ptr %465, align 2
  %467 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 231
  %468 = load i8, ptr @__anvill_stack_minus_137, align 1
  store i8 %468, ptr %467, align 1
  %469 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 232
  %470 = load i8, ptr @__anvill_stack_minus_136, align 1
  store i8 %470, ptr %469, align 8
  %471 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 233
  %472 = load i8, ptr @__anvill_stack_minus_135, align 1
  store i8 %472, ptr %471, align 1
  %473 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 234
  %474 = load i8, ptr @__anvill_stack_minus_134, align 1
  store i8 %474, ptr %473, align 2
  %475 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 235
  %476 = load i8, ptr @__anvill_stack_minus_133, align 1
  store i8 %476, ptr %475, align 1
  %477 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 236
  %478 = load i8, ptr @__anvill_stack_minus_132, align 1
  store i8 %478, ptr %477, align 4
  %479 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 237
  %480 = load i8, ptr @__anvill_stack_minus_131, align 1
  store i8 %480, ptr %479, align 1
  %481 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 238
  %482 = load i8, ptr @__anvill_stack_minus_130, align 1
  store i8 %482, ptr %481, align 2
  %483 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 239
  %484 = load i8, ptr @__anvill_stack_minus_129, align 1
  store i8 %484, ptr %483, align 1
  %485 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 240
  %486 = load i8, ptr @__anvill_stack_minus_128, align 1
  store i8 %486, ptr %485, align 8
  %487 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 241
  %488 = load i8, ptr @__anvill_stack_minus_127, align 1
  store i8 %488, ptr %487, align 1
  %489 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 242
  %490 = load i8, ptr @__anvill_stack_minus_126, align 1
  store i8 %490, ptr %489, align 2
  %491 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 243
  %492 = load i8, ptr @__anvill_stack_minus_125, align 1
  store i8 %492, ptr %491, align 1
  %493 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 244
  %494 = load i8, ptr @__anvill_stack_minus_124, align 1
  store i8 %494, ptr %493, align 4
  %495 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 245
  %496 = load i8, ptr @__anvill_stack_minus_123, align 1
  store i8 %496, ptr %495, align 1
  %497 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 246
  %498 = load i8, ptr @__anvill_stack_minus_122, align 1
  store i8 %498, ptr %497, align 2
  %499 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 247
  %500 = load i8, ptr @__anvill_stack_minus_121, align 1
  store i8 %500, ptr %499, align 1
  %501 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 248
  %502 = load i8, ptr @__anvill_stack_minus_120, align 1
  store i8 %502, ptr %501, align 8
  %503 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 249
  %504 = load i8, ptr @__anvill_stack_minus_119, align 1
  store i8 %504, ptr %503, align 1
  %505 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 250
  %506 = load i8, ptr @__anvill_stack_minus_118, align 1
  store i8 %506, ptr %505, align 2
  %507 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 251
  %508 = load i8, ptr @__anvill_stack_minus_117, align 1
  store i8 %508, ptr %507, align 1
  %509 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 252
  %510 = load i8, ptr @__anvill_stack_minus_116, align 1
  store i8 %510, ptr %509, align 4
  %511 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 253
  %512 = load i8, ptr @__anvill_stack_minus_115, align 1
  store i8 %512, ptr %511, align 1
  %513 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 254
  %514 = load i8, ptr @__anvill_stack_minus_114, align 1
  store i8 %514, ptr %513, align 2
  %515 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 255
  %516 = load i8, ptr @__anvill_stack_minus_113, align 1
  store i8 %516, ptr %515, align 1
  %517 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 256
  %518 = load i8, ptr @__anvill_stack_minus_112, align 1
  store i8 %518, ptr %517, align 8
  %519 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 257
  %520 = load i8, ptr @__anvill_stack_minus_111, align 1
  store i8 %520, ptr %519, align 1
  %521 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 258
  %522 = load i8, ptr @__anvill_stack_minus_110, align 1
  store i8 %522, ptr %521, align 2
  %523 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 259
  %524 = load i8, ptr @__anvill_stack_minus_109, align 1
  store i8 %524, ptr %523, align 1
  %525 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 260
  %526 = load i8, ptr @__anvill_stack_minus_108, align 1
  store i8 %526, ptr %525, align 4
  %527 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 261
  %528 = load i8, ptr @__anvill_stack_minus_107, align 1
  store i8 %528, ptr %527, align 1
  %529 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 262
  %530 = load i8, ptr @__anvill_stack_minus_106, align 1
  store i8 %530, ptr %529, align 2
  %531 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 263
  %532 = load i8, ptr @__anvill_stack_minus_105, align 1
  store i8 %532, ptr %531, align 1
  %533 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 264
  %534 = load i8, ptr @__anvill_stack_minus_104, align 1
  store i8 %534, ptr %533, align 8
  %535 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 265
  %536 = load i8, ptr @__anvill_stack_minus_103, align 1
  store i8 %536, ptr %535, align 1
  %537 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 266
  %538 = load i8, ptr @__anvill_stack_minus_102, align 1
  store i8 %538, ptr %537, align 2
  %539 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 267
  %540 = load i8, ptr @__anvill_stack_minus_101, align 1
  store i8 %540, ptr %539, align 1
  %541 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 268
  %542 = load i8, ptr @__anvill_stack_minus_100, align 1
  store i8 %542, ptr %541, align 4
  %543 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 269
  %544 = load i8, ptr @__anvill_stack_minus_99, align 1
  store i8 %544, ptr %543, align 1
  %545 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 270
  %546 = load i8, ptr @__anvill_stack_minus_98, align 1
  store i8 %546, ptr %545, align 2
  %547 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 271
  %548 = load i8, ptr @__anvill_stack_minus_97, align 1
  store i8 %548, ptr %547, align 1
  %549 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 272
  %550 = load i8, ptr @__anvill_stack_minus_96, align 1
  store i8 %550, ptr %549, align 8
  %551 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 273
  %552 = load i8, ptr @__anvill_stack_minus_95, align 1
  store i8 %552, ptr %551, align 1
  %553 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 274
  %554 = load i8, ptr @__anvill_stack_minus_94, align 1
  store i8 %554, ptr %553, align 2
  %555 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 275
  %556 = load i8, ptr @__anvill_stack_minus_93, align 1
  store i8 %556, ptr %555, align 1
  %557 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 276
  %558 = load i8, ptr @__anvill_stack_minus_92, align 1
  store i8 %558, ptr %557, align 4
  %559 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 277
  %560 = load i8, ptr @__anvill_stack_minus_91, align 1
  store i8 %560, ptr %559, align 1
  %561 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 278
  %562 = load i8, ptr @__anvill_stack_minus_90, align 1
  store i8 %562, ptr %561, align 2
  %563 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 279
  %564 = load i8, ptr @__anvill_stack_minus_89, align 1
  store i8 %564, ptr %563, align 1
  %565 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 280
  %566 = load i8, ptr @__anvill_stack_minus_88, align 1
  store i8 %566, ptr %565, align 8
  %567 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 281
  %568 = load i8, ptr @__anvill_stack_minus_87, align 1
  store i8 %568, ptr %567, align 1
  %569 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 282
  %570 = load i8, ptr @__anvill_stack_minus_86, align 1
  store i8 %570, ptr %569, align 2
  %571 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 283
  %572 = load i8, ptr @__anvill_stack_minus_85, align 1
  store i8 %572, ptr %571, align 1
  %573 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 284
  %574 = load i8, ptr @__anvill_stack_minus_84, align 1
  store i8 %574, ptr %573, align 4
  %575 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 285
  %576 = load i8, ptr @__anvill_stack_minus_83, align 1
  store i8 %576, ptr %575, align 1
  %577 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 286
  %578 = load i8, ptr @__anvill_stack_minus_82, align 1
  store i8 %578, ptr %577, align 2
  %579 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 287
  %580 = load i8, ptr @__anvill_stack_minus_81, align 1
  store i8 %580, ptr %579, align 1
  %581 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 288
  %582 = load i8, ptr @__anvill_stack_minus_80, align 1
  store i8 %582, ptr %581, align 8
  %583 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 289
  %584 = load i8, ptr @__anvill_stack_minus_79, align 1
  store i8 %584, ptr %583, align 1
  %585 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 290
  %586 = load i8, ptr @__anvill_stack_minus_78, align 1
  store i8 %586, ptr %585, align 2
  %587 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 291
  %588 = load i8, ptr @__anvill_stack_minus_77, align 1
  store i8 %588, ptr %587, align 1
  %589 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 292
  %590 = load i8, ptr @__anvill_stack_minus_76, align 1
  store i8 %590, ptr %589, align 4
  %591 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 293
  %592 = load i8, ptr @__anvill_stack_minus_75, align 1
  store i8 %592, ptr %591, align 1
  %593 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 294
  %594 = load i8, ptr @__anvill_stack_minus_74, align 1
  store i8 %594, ptr %593, align 2
  %595 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 295
  %596 = load i8, ptr @__anvill_stack_minus_73, align 1
  store i8 %596, ptr %595, align 1
  %597 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 296
  %598 = load i8, ptr @__anvill_stack_minus_72, align 1
  store i8 %598, ptr %597, align 8
  %599 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 297
  %600 = load i8, ptr @__anvill_stack_minus_71, align 1
  store i8 %600, ptr %599, align 1
  %601 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 298
  %602 = load i8, ptr @__anvill_stack_minus_70, align 1
  store i8 %602, ptr %601, align 2
  %603 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 299
  %604 = load i8, ptr @__anvill_stack_minus_69, align 1
  store i8 %604, ptr %603, align 1
  %605 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 300
  %606 = load i8, ptr @__anvill_stack_minus_68, align 1
  store i8 %606, ptr %605, align 4
  %607 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 301
  %608 = load i8, ptr @__anvill_stack_minus_67, align 1
  store i8 %608, ptr %607, align 1
  %609 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 302
  %610 = load i8, ptr @__anvill_stack_minus_66, align 1
  store i8 %610, ptr %609, align 2
  %611 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 303
  %612 = load i8, ptr @__anvill_stack_minus_65, align 1
  store i8 %612, ptr %611, align 1
  %613 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 304
  %614 = load i8, ptr @__anvill_stack_minus_64, align 1
  store i8 %614, ptr %613, align 8
  %615 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 305
  %616 = load i8, ptr @__anvill_stack_minus_63, align 1
  store i8 %616, ptr %615, align 1
  %617 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 306
  %618 = load i8, ptr @__anvill_stack_minus_62, align 1
  store i8 %618, ptr %617, align 2
  %619 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 307
  %620 = load i8, ptr @__anvill_stack_minus_61, align 1
  store i8 %620, ptr %619, align 1
  %621 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 308
  %622 = load i8, ptr @__anvill_stack_minus_60, align 1
  store i8 %622, ptr %621, align 4
  %623 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 309
  %624 = load i8, ptr @__anvill_stack_minus_59, align 1
  store i8 %624, ptr %623, align 1
  %625 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 310
  %626 = load i8, ptr @__anvill_stack_minus_58, align 1
  store i8 %626, ptr %625, align 2
  %627 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 311
  %628 = load i8, ptr @__anvill_stack_minus_57, align 1
  store i8 %628, ptr %627, align 1
  %629 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 312
  %630 = load i8, ptr @__anvill_stack_minus_56, align 1
  store i8 %630, ptr %629, align 8
  %631 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 313
  %632 = load i8, ptr @__anvill_stack_minus_55, align 1
  store i8 %632, ptr %631, align 1
  %633 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 314
  %634 = load i8, ptr @__anvill_stack_minus_54, align 1
  store i8 %634, ptr %633, align 2
  %635 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 315
  %636 = load i8, ptr @__anvill_stack_minus_53, align 1
  store i8 %636, ptr %635, align 1
  %637 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 316
  %638 = load i8, ptr @__anvill_stack_minus_52, align 1
  store i8 %638, ptr %637, align 4
  %639 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 317
  %640 = load i8, ptr @__anvill_stack_minus_51, align 1
  store i8 %640, ptr %639, align 1
  %641 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 318
  %642 = load i8, ptr @__anvill_stack_minus_50, align 1
  store i8 %642, ptr %641, align 2
  %643 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 319
  %644 = load i8, ptr @__anvill_stack_minus_49, align 1
  store i8 %644, ptr %643, align 1
  %645 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 320
  %646 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 328
  %647 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 336
  %648 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 344
  %649 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 352
  %650 = getelementptr inbounds %sub_401270__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 360
  %651 = load i64, ptr @__anvill_reg_RBX, align 8
  %652 = load i64, ptr @__anvill_reg_RBP, align 8
  %653 = load i64, ptr @__anvill_reg_R12, align 8
  %654 = load i64, ptr @__anvill_reg_R13, align 8
  %655 = load i64, ptr @__anvill_reg_R14, align 8
  %656 = load i64, ptr @__anvill_reg_R15, align 8
  %657 = bitcast ptr %650 to ptr
  store i64 %652, ptr %657, align 8
  %658 = bitcast ptr %649 to ptr
  store i64 %656, ptr %658, align 8
  %659 = bitcast ptr %648 to ptr
  store i64 %655, ptr %659, align 8
  %660 = bitcast ptr %647 to ptr
  store i64 %654, ptr %660, align 8
  %661 = bitcast ptr %646 to ptr
  store i64 %653, ptr %661, align 8
  %662 = bitcast ptr %645 to ptr
  store i64 %651, ptr %662, align 8
  %663 = add i32 %0, -1
  %664 = icmp ne i32 %663, 0
  %665 = lshr i32 %663, 31
  %666 = lshr i32 %0, 31
  %667 = xor i32 %665, %666
  %668 = add nuw nsw i32 %667, %666
  %669 = icmp eq i32 %668, 2
  %670 = icmp sgt i32 %663, -1
  %671 = xor i1 %670, %669
  %672 = and i1 %664, %671
  %673 = bitcast ptr %133 to ptr
  br i1 %672, label %674, label %687

674:                                              ; preds = %3
  store i64 4199089, ptr %673, align 8
  %675 = call ptr @sub_404158__A_Sb_Sb_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_B_78(ptr nonnull getelementptr inbounds ([19 x i8], ptr @var_40203a__Cbx19_D, i32 0, i32 0), ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_40204d__Cbx1_D, i32 0, i32 0))
  %676 = ptrtoint ptr %675 to i64
  %677 = bitcast ptr %229 to ptr
  store i64 %676, ptr %677, align 8
  store i64 4199123, ptr %673, align 8
  %678 = call i32 (ptr, i64, ptr, ...) @sub_4041c0__A_Sbl_Sb_Vi_B_78(ptr nonnull %321, i64 10, ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_40204f__Cbx1_D, i32 0, i32 0))
  store i64 4199148, ptr %673, align 8
  %679 = call i32 @sub_4041c8__Aiiii_B_78(i32 29, i32 3, i32 1)
  %680 = zext i32 %679 to i64
  %681 = bitcast ptr %213 to ptr
  store i64 %680, ptr %681, align 8
  %682 = bitcast ptr %197 to ptr
  store i32 %679, ptr %682, align 8
  %683 = bitcast ptr %197 to ptr
  store i64 4199170, ptr %673, align 8
  %684 = call i64 @sub_401610__A_Si_Sbl_B_0(ptr nonnull %683, ptr nonnull %321)
  %685 = trunc i64 %684 to i32
  %686 = icmp eq i32 %685, 0
  br i1 %686, label %689, label %692

687:                                              ; preds = %3
  store i64 4199064, ptr %673, align 8
  %688 = call i32 (ptr, ...) @sub_404190__A_Sb_Vi_B_78(ptr nonnull getelementptr inbounds ([26 x i8], ptr @var_402020__Cbx26_D, i32 0, i32 0))
  br label %911

689:                                              ; preds = %692, %674
  store i64 4199229, ptr %673, align 8
  %690 = call i32 @sub_404198__A_Sbi_B_78(ptr nonnull getelementptr inbounds ([15 x i8], ptr @var_4020b5__Cbx15_D, i32 0, i32 0))
  store i64 4199236, ptr %673, align 8
  %691 = call i64 @sub_4016e0__Avl_B_0()
  br label %698

692:                                              ; preds = %692, %674
  store i64 4199194, ptr %673, align 8
  %693 = call i32 @sub_404198__A_Sbi_B_78(ptr nonnull getelementptr inbounds ([24 x i8], ptr @var_4020c4__Cbx24_D, i32 0, i32 0))
  store i64 4199204, ptr %673, align 8
  %694 = call i32 @sub_4041b8__Aii_B_78(i32 3000)
  store i64 4199215, ptr %673, align 8
  %695 = call i64 @sub_401610__A_Si_Sbl_B_0(ptr nonnull %683, ptr nonnull %321)
  %696 = trunc i64 %695 to i32
  %697 = icmp eq i32 %696, 0
  br i1 %697, label %689, label %692

698:                                              ; preds = %698, %689
  %699 = phi i64 [ 9, %689 ], [ %722, %698 ]
  %700 = phi i32 [ 9, %689 ], [ %723, %698 ]
  %701 = phi i32 [ 8, %689 ], [ %721, %698 ]
  %702 = phi i32 [ 8, %689 ], [ %700, %698 ]
  %703 = phi i32 [ 7, %689 ], [ %701, %698 ]
  %704 = phi i32 [ 7, %689 ], [ %702, %698 ]
  %705 = phi i32 [ 6, %689 ], [ %703, %698 ]
  %706 = phi i32 [ 6, %689 ], [ %704, %698 ]
  %707 = phi i32 [ 5, %689 ], [ %705, %698 ]
  %708 = phi i32 [ 5, %689 ], [ %706, %698 ]
  %709 = phi i32 [ 4, %689 ], [ %707, %698 ]
  %710 = phi i32 [ 4, %689 ], [ %708, %698 ]
  %711 = phi i32 [ 3, %689 ], [ %709, %698 ]
  %712 = phi i32 [ 3, %689 ], [ %710, %698 ]
  %713 = phi i32 [ 2, %689 ], [ %711, %698 ]
  %714 = phi i32 [ 2, %689 ], [ %712, %698 ]
  %715 = phi i32 [ 1, %689 ], [ %713, %698 ]
  store i64 4199265, ptr %673, align 8
  %716 = call i64 @sub_401a70__Ailil_B_0(i32 %715, i64 4202578, i32 5)
  store i64 4199277, ptr %673, align 8
  %717 = call i64 @sub_401af0__Aiil_B_0(i32 %715, i32 10)
  store i64 4199289, ptr %673, align 8
  %718 = call i64 @sub_401920__Aiil_B_0(i32 %715, i32 1)
  %719 = icmp eq i32 %714, 5
  %720 = add i64 %699, 1
  %721 = trunc i64 %699 to i32
  %722 = and i64 %720, 4294967295
  %723 = trunc i64 %720 to i32
  br i1 %719, label %724, label %698

724:                                              ; preds = %698
  store i64 4199307, ptr %673, align 8
  %725 = call ptr @sub_404178__Al_Sb_B_78(i64 32)
  %726 = ptrtoint ptr %725 to i64
  %727 = bitcast ptr %725 to ptr
  store i64 4199318, ptr %673, align 8
  %728 = call i64 @sub_401b80__A_Sll_B_0(ptr %727)
  %729 = load i64, ptr %681, align 8
  %730 = and i64 %729, 63
  switch i64 %730, label %731 [
    i64 0, label %736
    i64 1, label %734
  ]

731:                                              ; preds = %724
  %732 = add nsw i64 %730, -1
  %733 = shl i64 2, %732
  br label %734

734:                                              ; preds = %731, %724
  %735 = phi i64 [ %733, %731 ], [ 2, %724 ]
  br label %736

736:                                              ; preds = %734, %724
  %737 = phi i64 [ %735, %734 ], [ 1, %724 ]
  %738 = trunc i64 %729 to i32
  %739 = icmp sgt i32 %738, -1
  %740 = bitcast ptr %261 to ptr
  store i64 %737, ptr %740, align 8
  %741 = add i32 %738, 1
  %742 = bitcast ptr %205 to ptr
  store i32 %741, ptr %742, align 4
  %743 = shl i64 %729, 32
  %744 = add i64 %743, 270582939648
  %745 = ashr i64 %743, 38
  %746 = ashr i64 %744, 38
  %747 = select i1 %739, i64 %745, i64 %746
  %748 = bitcast ptr %245 to ptr
  store i64 %747, ptr %748, align 8
  %749 = bitcast ptr %189 to ptr
  store i32 0, ptr %749, align 4
  br label %750

750:                                              ; preds = %796, %736
  %751 = phi i64 [ 4199462, %736 ], [ %797, %796 ]
  %752 = phi i64 [ 4199392, %736 ], [ %798, %796 ]
  %753 = ptrtoint ptr %389 to i64
  br label %754

754:                                              ; preds = %754, %750
  %755 = phi i64 [ %753, %750 ], [ %758, %754 ]
  %756 = phi i64 [ 16, %750 ], [ %759, %754 ]
  %757 = inttoptr i64 %755 to ptr
  store i64 0, ptr %757, align 8
  %758 = add i64 %755, 8
  %759 = add i64 %756, -1
  %760 = icmp eq i64 %759, 0
  br i1 %760, label %761, label %754

761:                                              ; preds = %754
  %762 = load i64, ptr %740, align 8
  %763 = load i64, ptr %748, align 8
  %764 = shl i64 %763, 3
  %765 = add i64 %764, %753
  %766 = inttoptr i64 %765 to ptr
  %767 = load i64, ptr %766, align 8
  %768 = or i64 %767, %762
  store i64 %768, ptr %766, align 8
  %769 = bitcast ptr %341 to ptr
  store i64 0, ptr %769, align 8
  %770 = bitcast ptr %357 to ptr
  store i64 50, ptr %770, align 8
  %771 = load i32, ptr %742, align 4
  store i64 %751, ptr %673, align 8
  %772 = bitcast ptr %389 to ptr
  %773 = bitcast ptr %341 to ptr
  %774 = call i32 @sub_4041a8__Ai_S_X0_E_Clx16_D_F_S_M0_S_M0_S_X1_Ell_Fi_B_78(i32 %771, ptr nonnull %772, ptr null, ptr null, ptr nonnull %773)
  %775 = icmp slt i32 %774, 1
  %776 = select i1 %775, i64 309, i64 78
  %777 = add i64 %752, %776
  %778 = add i64 %777, -309
  %779 = add i64 %777, -239
  %780 = add i64 %777, 177
  %781 = add i64 %777, 108
  %782 = add i64 %777, 86
  %783 = add i64 %777, 64
  %784 = add i64 %777, 42
  %785 = add i64 %777, 16
  %786 = add i64 %777, 8
  br i1 %775, label %796, label %787

787:                                              ; preds = %761
  %788 = load i64, ptr %681, align 8
  %789 = add i64 %777, 18
  store i64 %789, ptr %673, align 8
  %790 = trunc i64 %788 to i32
  %791 = call i64 @sub_4041a0__Ai_Sbll_B_78(i32 %790, ptr nonnull %149, i64 16)
  %792 = icmp sgt i64 %791, -1
  %793 = select i1 %792, i64 27, i64 420
  %794 = add i64 %777, %793
  %795 = icmp slt i64 %791, 0
  br i1 %795, label %830, label %832

796:                                              ; preds = %898, %885, %873, %761
  %797 = phi i64 [ %779, %761 ], [ %877, %873 ], [ %890, %885 ], [ %903, %898 ]
  %798 = phi i64 [ %778, %761 ], [ %876, %873 ], [ %889, %885 ], [ %902, %898 ]
  %799 = phi i64 [ %780, %761 ], [ %878, %873 ], [ %891, %885 ], [ %904, %898 ]
  %800 = phi i64 [ %781, %761 ], [ %879, %873 ], [ %892, %885 ], [ %905, %898 ]
  %801 = phi i64 [ %782, %761 ], [ %880, %873 ], [ %893, %885 ], [ %906, %898 ]
  %802 = phi i64 [ %783, %761 ], [ %881, %873 ], [ %894, %885 ], [ %907, %898 ]
  %803 = phi i64 [ %784, %761 ], [ %882, %873 ], [ %895, %885 ], [ %908, %898 ]
  %804 = phi i64 [ %785, %761 ], [ %883, %873 ], [ %896, %885 ], [ %909, %898 ]
  %805 = phi i64 [ %786, %761 ], [ %884, %873 ], [ %897, %885 ], [ %910, %898 ]
  store i64 %805, ptr %673, align 8
  %806 = call i64 @sub_401c60__A_Sbl_B_0(ptr %725)
  store i64 %804, ptr %673, align 8
  call void @sub_401cd0__A_Sbv_B_0(ptr %725)
  %807 = load i8, ptr %725, align 1
  %808 = icmp eq i8 %807, 0
  store i64 %803, ptr %673, align 8
  %809 = select i1 %808, i32 10, i32 100
  %810 = call i64 @sub_401af0__Aiil_B_0(i32 1, i32 %809)
  %811 = add i64 %726, 1
  %812 = inttoptr i64 %811 to ptr
  %813 = load i8, ptr %812, align 1
  %814 = icmp eq i8 %813, 0
  store i64 %802, ptr %673, align 8
  %815 = select i1 %814, i32 10, i32 100
  %816 = call i64 @sub_401af0__Aiil_B_0(i32 2, i32 %815)
  %817 = add i64 %726, 2
  %818 = inttoptr i64 %817 to ptr
  %819 = load i8, ptr %818, align 1
  %820 = icmp eq i8 %819, 0
  store i64 %801, ptr %673, align 8
  %821 = select i1 %820, i32 10, i32 100
  %822 = call i64 @sub_401af0__Aiil_B_0(i32 3, i32 %821)
  %823 = add i64 %726, 3
  %824 = inttoptr i64 %823 to ptr
  %825 = load i8, ptr %824, align 1
  %826 = icmp eq i8 %825, 0
  store i64 %800, ptr %673, align 8
  %827 = select i1 %826, i32 10, i32 100
  %828 = call i64 @sub_401af0__Aiil_B_0(i32 4, i32 %827)
  store i64 %799, ptr %673, align 8
  %829 = call i32 (ptr, ...) @sub_404190__A_Sb_Vi_B_78(ptr nonnull getelementptr inbounds ([21 x i8], ptr @var_40209c__Cbx21_D, i32 0, i32 0))
  br label %750

830:                                              ; preds = %787
  %831 = add i64 %794, 10
  store i64 %831, ptr %673, align 8
  call void @sub_404188__A_Sbv_B_78(ptr nonnull getelementptr inbounds ([9 x i8], ptr @var_402057__Cbx9_D, i32 0, i32 0))
  store i32 1, ptr %749, align 4
  br label %911

832:                                              ; preds = %787
  %833 = bitcast ptr %149 to ptr
  %834 = load i32, ptr %833, align 8
  %835 = and i32 %834, 536870911
  store i32 %835, ptr %833, align 8
  %836 = add i64 %794, 30
  store i64 %836, ptr %673, align 8
  %837 = bitcast ptr %373 to ptr
  %838 = call i64 @sub_4041d8__A_Sll_B_78(ptr nonnull %837)
  %839 = add i64 %794, 38
  store i64 %839, ptr %673, align 8
  %840 = call ptr @sub_404150__A_Sl_Sb_B_78(ptr nonnull %837)
  %841 = load i8, ptr %167, align 1
  %842 = zext i8 %841 to i64
  %843 = bitcast ptr %293 to ptr
  store i64 %842, ptr %843, align 8
  %844 = load i8, ptr %169, align 2
  %845 = zext i8 %844 to i64
  %846 = bitcast ptr %277 to ptr
  store i64 %845, ptr %846, align 8
  %847 = load i8, ptr %171, align 1
  %848 = zext i8 %847 to i64
  %849 = load i8, ptr %173, align 4
  %850 = zext i8 %849 to i64
  %851 = load i8, ptr %175, align 1
  %852 = zext i8 %851 to i64
  %853 = load i8, ptr %177, align 2
  %854 = zext i8 %853 to i64
  %855 = load i8, ptr %179, align 1
  %856 = zext i8 %855 to i64
  %857 = bitcast ptr %229 to ptr
  %858 = load ptr, ptr %857, align 8
  %859 = bitcast ptr %117 to ptr
  store i64 %856, ptr %859, align 8
  %860 = bitcast ptr %101 to ptr
  store i64 %854, ptr %860, align 8
  %861 = bitcast ptr %85 to ptr
  store i64 %852, ptr %861, align 8
  %862 = bitcast ptr %69 to ptr
  store i64 %850, ptr %862, align 8
  %863 = bitcast ptr %53 to ptr
  store i64 %848, ptr %863, align 8
  %864 = bitcast ptr %37 to ptr
  store i64 %845, ptr %864, align 8
  %865 = bitcast ptr %21 to ptr
  store i64 %842, ptr %865, align 8
  %866 = add i64 %794, 150
  %867 = bitcast ptr %4 to ptr
  store i64 %866, ptr %867, align 8
  %868 = call i32 (ptr, ptr, ...) @sub_404160__A_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_Sb_Vi_B_78(ptr %858, ptr nonnull getelementptr inbounds ([56 x i8], ptr @var_402060__Cbx56_D, i32 0, i32 0))
  %869 = and i32 %834, 134217472
  %870 = icmp eq i32 %869, 16632832
  %871 = select i1 %870, i64 191, i64 168
  %872 = add i64 %794, %871
  br i1 %870, label %873, label %885

873:                                              ; preds = %832
  %874 = add i64 %872, 13
  store i64 %874, ptr %673, align 8
  %875 = call i64 @sub_4016d0__A_Sb_Sbl_B_0(ptr nonnull %165, ptr %725)
  %876 = add i64 %872, -296
  %877 = add i64 %872, -226
  %878 = add i64 %874, 177
  %879 = add i64 %874, 108
  %880 = add i64 %874, 86
  %881 = add i64 %874, 64
  %882 = add i64 %874, 42
  %883 = add i64 %874, 16
  %884 = add i64 %874, 8
  br label %796

885:                                              ; preds = %832
  %886 = icmp eq i32 %869, 16707840
  %887 = select i1 %886, i64 8, i64 36
  %888 = add i64 %872, %887
  %889 = add i64 %888, -309
  %890 = add i64 %888, -239
  %891 = add i64 %888, 177
  %892 = add i64 %888, 108
  %893 = add i64 %888, 86
  %894 = add i64 %888, 64
  %895 = add i64 %888, 42
  %896 = add i64 %888, 16
  %897 = add i64 %888, 8
  br i1 %886, label %898, label %796

898:                                              ; preds = %885
  %899 = add i64 %888, 13
  store i64 %899, ptr %673, align 8
  %900 = call i64 @sub_401690__A_Sb_Sbl_B_0(ptr nonnull %165, ptr %725)
  %901 = add i64 %888, 28
  %902 = add i64 %888, -281
  %903 = add i64 %888, -211
  %904 = add i64 %901, 177
  %905 = add i64 %901, 108
  %906 = add i64 %901, 86
  %907 = add i64 %901, 64
  %908 = add i64 %901, 42
  %909 = add i64 %901, 16
  %910 = add i64 %901, 8
  br label %796

911:                                              ; preds = %830, %687
  ret i32 1
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_S_Sb(i64) local_unnamed_addr #2

; Function Attrs: noinline
declare x86_64_sysvcc ptr @sub_404158__A_Sb_Sb_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_B_78(ptr, ptr) #0

; Function Attrs: readnone
declare ptr @__anvill_type_hint_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F(i64) local_unnamed_addr #2

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Sb(i64) local_unnamed_addr #2

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_4041c0__A_Sbl_Sb_Vi_B_78(ptr, i64, ptr, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_4041c8__Aiiii_B_78(i32, i32, i32) #0

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_32(ptr, i64, i32) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Si(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404190__A_Sb_Vi_B_78(ptr, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404198__A_Sbi_B_78(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_4041b8__Aii_B_78(i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @sub_404178__Al_Sb_B_78(i64) #0

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Sl(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(ptr, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_S_X0_Ell_F(i64) local_unnamed_addr #2

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_4041a8__Ai_S_X0_E_Clx16_D_F_S_M0_S_M0_S_X1_Ell_Fi_B_78(i32, ptr, ptr, ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @sub_4041a0__Ai_Sbll_B_78(i32, ptr, i64) #0

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i8 @__remill_read_memory_8(ptr, i64) local_unnamed_addr #1

; Function Attrs: noinline
declare x86_64_sysvcc void @sub_404188__A_Sbv_B_78(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @sub_4041d8__A_Sll_B_78(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @sub_404150__A_Sl_Sb_B_78(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404160__A_S_X0_Ei_CBx4_D_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_Sb_S_X1_E_S_M1_S_M0i_CBx4_D_F_S_M0iilhb_Cbx1_D_CBx4_D_S_X2_Eii_Sb_Fl_S_X3_E_X4_E_S_X5_E_S_X6_E_Sbi_CBx4_D_Sb_Sv_Sv_Sv_F_Sbi_CBx4_D_Sb_Sb_Sv_Sv_Sv_Sviiiii_CBx4_D_Sb_F_X7_E_Sb_Sbiii_CBx4_D_S_X8_Ei_X9_E_Cbx4_D_F_F_M8_F_F_M4_F_S_X10_E_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_Si_M8_M8_M3_Cix1_D_CBx4_D_S_X11_Ell_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_Sv_F_F_S_M0_Sbli_Cbx20_D_F_Sb_Vi_B_78(ptr, ptr, ...) #0

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #3

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404138__A_Svi_S_Sb_Sv_Sv_Sv_Sbi_B_78(ptr, i32, ptr, ptr, ptr, ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @sub_4041d0__A_Sb_Sb_Sb_B_78(ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_4041b0__Aiii_Sbii_B_78(i32, i32, i32, ptr, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @sub_4041e0__Ai_Sbll_B_78(i32, ptr, i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @sub_404148__Avl_B_78() #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @sub_404170__Ailil_B_78(i32, i64, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404168__Ail_Vi_B_78(i32, i64, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404140__Ai_S_X0_Eh_Cbx14_D_Fii_B_78(i32, ptr, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sub_404180__A_Sbi_Vi_B_78(ptr, i32, ...) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
