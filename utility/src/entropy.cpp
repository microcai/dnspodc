
#include <random>
#include <string>

#include "../include/entropy.hpp"


static thread_local std::mt19937 per_thread_mt19937 = std::mt19937(std::random_device()());

std::mt19937& get_local_mt()
{
	return per_thread_mt19937;
}

