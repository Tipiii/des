from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .forms import RegisterForm
from .models import Message
from .des_utils import encrypt_des, decrypt_des
from django.db.models import Q
import base64
import binascii

# ---------- Đăng ký ----------
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('send')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})


# ---------- Đăng nhập ----------
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('send')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})


# ---------- Gửi tin nhắn ----------
@login_required
def send_view(request):
    users = User.objects.all()
    context = {"users": users}

    if request.method == 'POST':
        receiver_id = request.POST['receiver']
        message = request.POST.get('message', '')
        image_file = request.FILES.get('image')
        key_hex = request.POST.get('key', '')

        if not key_hex or len(key_hex) != 16:
            context['error'] = '⚠️ Khóa DES phải là 16 ký tự hex (64-bit).'
            return render(request, 'send.html', context)

        try:
            key = binascii.unhexlify(key_hex)
        except:
            context['error'] = '⚠️ Khóa không hợp lệ! Phải là chuỗi hex.'
            return render(request, 'send.html', context)

        receiver = User.objects.get(id=receiver_id)
        ciphertext = encrypt_des(message, key) if message else ''

        encrypted_image = None
        if image_file:
            img_data = image_file.read()
            encrypted_image = encrypt_des(img_data.decode('latin1'), key).encode('latin1')

        Message.objects.create(
            sender=request.user,
            receiver=receiver,
            plaintext=message,
            ciphertext=ciphertext,
            image_cipher=encrypted_image
        )

        context['success'] = '✅ Tin nhắn đã được mã hóa và gửi!'
    return render(request, 'send.html', context)


# ---------- Hộp thư ----------
@login_required
def inbox_view(request):
    messages = Message.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user)
    ).order_by('-created_at')

    all_messages = []
    for msg in messages:
        all_messages.append({
            'id': msg.id,
            'from': msg.sender.username,
            'to': msg.receiver.username,
            'created_at': msg.created_at,
            'ciphertext': msg.ciphertext,
            'is_sent': msg.sender == request.user,
            'has_image': msg.image_cipher is not None
        })

    context = {'messages': all_messages}

    if request.method == 'POST':
        msg_id = request.POST.get('msg_id')
        key_hex = request.POST.get('key', '')

        try:
            msg = Message.objects.get(id=msg_id)

            # Kiểm tra nếu người dùng không phải người gửi/nhận thì không cho xem
            if msg.sender != request.user and msg.receiver != request.user:
                raise PermissionError("Không có quyền giải mã tin nhắn này!")

            if not key_hex or len(key_hex) != 16:
                raise ValueError("Khóa hex không hợp lệ!")

            key = binascii.unhexlify(key_hex)

            decrypted_text = decrypt_des(msg.ciphertext, key) if msg.ciphertext else ''

            decrypted_image = None
            if msg.image_cipher:
                decrypted_image_bytes = decrypt_des(msg.image_cipher.decode('latin1'), key)
                image_base64 = base64.b64encode(decrypted_image_bytes.encode('latin1')).decode()
                decrypted_image = f"data:image/jpeg;base64,{image_base64}"

            context['decrypted_id'] = msg.id
            context['decrypted_text'] = decrypted_text
            context['decrypted_image'] = decrypted_image

        except Exception as e:
            context['error'] = '❌ Giải mã thất bại. Có thể khóa sai hoặc không hợp lệ.'

    return render(request, 'inbox.html', context)



# ---------- Đăng xuất ----------
def logout_view(request):
    logout(request)
    return redirect('login')
