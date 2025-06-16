from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from .forms import RegisterForm
from .models import Message
from .des_utils import encrypt_des, decrypt_des
import os

# ---------- Đăng ký ----------
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # tự đăng nhập sau đăng ký
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
from .des_utils import encrypt_des, decrypt_des, generate_des_key
from .models import Message
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

@login_required
def send_view(request):
    users = User.objects.all()  # Cho phép gửi cho chính mình
    context = {"users": users}
    if request.method == 'POST':
        receiver_id = request.POST['receiver']
        message = request.POST['message']

        receiver = User.objects.get(id=receiver_id)
        key = generate_des_key()
        ciphertext = encrypt_des(message, key)

        Message.objects.create(
            sender=request.user,
            receiver=receiver,
            plaintext=message,
            ciphertext=ciphertext,
            des_key=key
        )
        context['success'] = 'Tin nhắn đã được mã hóa và gửi!'
    return render(request, 'send.html', context)

@login_required
def inbox_view(request):
    messages = Message.objects.filter(receiver=request.user).order_by('-created_at')

    decrypted_messages = []
    for msg in messages:
        try:
            decrypted_text = decrypt_des(msg.ciphertext, msg.des_key)
        except:
            decrypted_text = "(Giải mã thất bại)"
        decrypted_messages.append({
            'sender': msg.sender,
            'text': decrypted_text,
            'created_at': msg.created_at
        })

    return render(request, 'inbox.html', {'messages': decrypted_messages})


# ---------- Đăng xuất ----------
from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('login')  # Đảm bảo 'login' là tên URL đúng

