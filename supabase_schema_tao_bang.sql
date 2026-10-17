-- 1. BẢNG ACCOUNTS (Lưu trữ thông tin người dùng, mật khẩu/key, phân quyền, bộ môn)
CREATE TABLE public.accounts (
    code text PRIMARY KEY,              -- Mã truy cập (ví dụ: GV_HUNG, ADMIN2026)
    name text NOT NULL,                 -- Họ và tên
    role text NOT NULL,                 -- Tên quyền (VD: 'Giảng viên', 'CTSV')
    raw_role text NOT NULL,             -- Mã quyền nội bộ ('Admin', 'GV', 'CNBM', 'CTSV')
    major text,                         -- Chuyên ngành/bộ môn (VD: 'IT', 'MK'...) - dành cho GV/CNBM
    is_active boolean DEFAULT true,     -- Trạng thái tắt/mở tài khoản
    created_at timestamp with time zone DEFAULT now()
);

-- 2. BẢNG STUDENTS (Lưu trữ hồ sơ và trạng thái sinh viên chính)
CREATE TABLE public.students (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mssv text UNIQUE NOT NULL,          -- Mã số SV (Ví dụ: PH00001)
    ho_ten text NOT NULL,               -- Đầy đủ họ tên
    status text DEFAULT 'green',        -- 'green' (ổn định), 'yellow' (cần chú ý), 'red' (cảnh báo)
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

-- 2.1 BẢNG TRUNG GIAN KHÓA HỌC (Lưu thông tin Giảng viên X dạy Sinh viên Y ở Lớp Z)
CREATE TABLE public.student_classes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    student_id bigint REFERENCES public.students(id) ON DELETE CASCADE,
    author_code text REFERENCES public.accounts(code) ON DELETE CASCADE,
    class_name text NOT NULL,           -- Khóa học (VD: IT18301)
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(student_id, author_code, class_name) -- Tránh trùng lặp khi 1 thầy gán nhiều lần cùng 1 lớp
);

-- 3. BẢNG FEEDBACKS (Tách riêng để tối ưu việc xử lý Bình luận gốc & Reply)
-- (Nếu lưu Feedback chung vào bảng Sinh viên, ta sẽ không thể truy vấn hay làm thống kê Analytics một cách dễ dàng)
CREATE TABLE public.feedbacks (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    student_id bigint REFERENCES public.students(id) ON DELETE CASCADE,  -- Thuộc về sinh viên nào
    author_code text REFERENCES public.accounts(code) ON DELETE SET NULL,-- Ai là người viết
    author_name text NOT NULL,                                           -- Tên người viết lúc gửi
    role text NOT NULL,                                                  -- Role lúc gửi ('GV', 'CTSV'...)
    content text NOT NULL,                                               -- Nội dung
    reactions jsonb DEFAULT '[]'::jsonb,                                 -- Chứa số like tim (VD: [{code:'GV_HUNG'}])
    parent_id bigint REFERENCES public.feedbacks(id) ON DELETE CASCADE,  -- Nếu có ID => Đây là reply bình luận
    created_at timestamp with time zone DEFAULT now()
);

-- 4. BẢNG BUG REPORTS (Lưu trữ báo cáo lỗi/góp ý từ người dùng)
CREATE TABLE public.bug_reports (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    author_code text REFERENCES public.accounts(code) ON DELETE CASCADE,
    author_name text NOT NULL,
    role text NOT NULL,
    content text NOT NULL,
    status text DEFAULT 'pending',
    created_at timestamp with time zone DEFAULT now()
);

-- 5. BẢNG STUDENT_ROSTER (Lưu trữ danh sách sinh viên nhập khẩu từ Excel)
CREATE TABLE public.student_roster (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mssv text NOT NULL,
    ho_ten text NOT NULL,
    lop text,
    ma_mon text,
    giang_vien text,
    nganh text,
    created_at timestamp with time zone DEFAULT now()
);

-- --- QUYỀN BẢO MẬT RLS (ROW LEVEL SECURITY) TẠM THỜI CHO DEVELOPMENT ---
-- Chú ý: Vì dùng "Anon Key" thay cho code backend, để gọi được API, ta cần Bypass chính sách RLS
ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.student_classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feedbacks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bug_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.student_roster ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Cho phép Frontend đọc/ghi Accounts tự do (DEV)"  ON public.accounts  FOR ALL USING (true);
CREATE POLICY "Cho phép Frontend đọc/ghi Students tự do (DEV)"  ON public.students  FOR ALL USING (true);
CREATE POLICY "Cho phép Frontend đọc/ghi StudentClasses (DEV)"  ON public.student_classes  FOR ALL USING (true);
CREATE POLICY "Cho phép Frontend đọc/ghi Feedbacks tự do (DEV)" ON public.feedbacks FOR ALL USING (true);
CREATE POLICY "Cho phép Frontend đọc/ghi Bug Reports tự do (DEV)" ON public.bug_reports FOR ALL USING (true);
CREATE POLICY "Cho phép Frontend đọc/ghi Student Roster tự do (DEV)" ON public.student_roster FOR ALL USING (true);

-- --- ĐỔ DỮ LIỆU TÀI KHOẢN MẪU BAN ĐẦU ĐỂ TEST ---
INSERT INTO public.accounts (code, name, role, raw_role, major) VALUES
('ADMIN2026', 'Quản trị viên', 'Admin', 'Admin', 'Computing'),
('GV_HUNG', 'Thầy Hưng', 'Giảng viên', 'GV', 'Computing'),
('GV_LAN', 'Cô Lan', 'Giảng viên', 'GV', 'Business'),
('CNBM_IT', 'Cô Phương', 'Chủ nhiệm bộ môn', 'CNBM', 'Computing'),
('CTSV_TOAN', 'Thầy Toàn', 'CTSV', 'CTSV', null);
